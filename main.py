import argparse
import errno
import json
import requests
from src.dataset_manager import DatasetManager
from src.pir_server import PIRServer
from src.transport import LocalTransport, HTTPTransport, make_http_server
from src.client_proxy import ClientProxy
from src.dns_proxy import serve_dns


def main():
    parser = argparse.ArgumentParser(description='Page-partitioned BFV PIR DNS')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('demo', 'server'):
        p = sub.add_parser(name)
        p.add_argument('--dataset', default='data/demo.csv')
        p.add_argument('--page-size', type=int, default=8)
        p.add_argument('--seed', type=int, default=0)
        if name == 'server':
            p.add_argument('--host', default='127.0.0.1')
            p.add_argument('--port', type=int, default=8080)
            p.add_argument('--cert')
            p.add_argument('--key')
        else:
            p.add_argument('--domain', default='site000.example')
    for name in ('query', 'shell', 'proxy', 'dashboard'):
        p = sub.add_parser(name)
        p.add_argument('--server', default='http://127.0.0.1:8080')
        p.add_argument('--ca', help='CA certificate file for HTTPS')
        p.add_argument('--cache-pages', type=int, default=1 if name == 'dashboard' else 16,
                       choices=[1] if name == 'dashboard' else None)
        if name == 'query':
            p.add_argument('domain')
        if name == 'proxy':
            p.add_argument('--port', type=int, default=5353)
        if name == 'dashboard':
            p.set_defaults(server='http://127.0.0.1:8081')
            p.add_argument('--port', type=int, default=8090)
    args = parser.parse_args()
    if args.command in ('demo', 'server'):
        dataset = DatasetManager.from_csv(args.dataset, page_size=args.page_size, seed=args.seed)
        server = PIRServer(dataset)
        if args.command == 'server':
            try:
                httpd = make_http_server(server, args.host, args.port, args.cert, args.key)
            except OSError as exc:
                if exc.errno == errno.EADDRINUSE:
                    parser.exit(1, f'Port {args.port} on {args.host} is already in use. '
                                'Choose another port with --port 8081, and use '
                                '--server http://127.0.0.1:8081 on the client.\n')
                raise
            scheme = 'https' if args.cert else 'http'
            print(f'PIR server at {scheme}://{args.host}:{httpd.server_port}: '
                  f'{len(dataset.pages)} pages x {dataset.page_size} records', flush=True)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
            return
        client = ClientProxy(LocalTransport(server))
        for _ in range(2):
            print(args.domain, client.query(args.domain), json.dumps(client.stats()))
        return
    try:
        client = ClientProxy(HTTPTransport(args.server, args.ca or True), args.cache_pages)
    except requests.exceptions.SSLError:
        parser.exit(1, f'TLS verification failed for {args.server}. Check the certificate and --ca file.\n')
    except requests.exceptions.ConnectionError:
        parser.exit(1, f'Cannot connect to {args.server}. Start the PIR server in another '
                    'terminal with the matching --port and leave it running.\n')
    except requests.exceptions.Timeout:
        parser.exit(1, f'Timed out connecting to {args.server}. Check that the server is running.\n')
    if args.command == 'query':
        print(json.dumps({'domain': args.domain, 'answer': client.query(args.domain), 'metrics': client.stats()}, indent=2))
    elif args.command == 'proxy':
        serve_dns(client, port=args.port)
    elif args.command == 'dashboard':
        from src.dashboard import serve_dashboard
        try:
            serve_dashboard(client, args.port)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                parser.exit(1, f'Dashboard port {args.port} is in use; choose another with --port.\n')
            raise
    else:
        print('Enter a domain, stats, pages, cached, sample, resize N, or quit.')
        while True:
            try:
                line = input('pir-dns> ').strip()
                if line in ('quit', 'exit'):
                    break
                if line == 'stats':
                    print(json.dumps(client.stats(), indent=2))
                elif line == 'pages':
                    print([len(p) for p in client.manifest['pages']])
                elif line == 'cached':
                    print({p: list(r) for p, r in client.cache.pages.items()})
                elif line == 'sample':
                    print(list(client.index)[:10])
                elif line.startswith('resize '):
                    client.cache.resize(int(line.split()[1]))
                elif line:
                    print(client.query(line))
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as exc:
                print(f'Error: {exc}')


if __name__ == '__main__':
    main()
