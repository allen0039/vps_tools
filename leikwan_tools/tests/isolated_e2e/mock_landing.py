#!/usr/bin/env python3
"""Mock TCP landing server reporting its own identity and observed peer source IPv4."""

import argparse
import socketserver


def make_handler(landing_id: str):
    class LandingHandler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            peer_ip, peer_port = self.client_address[0], self.client_address[1]
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                print(
                    f"[LANDING_OBS] id={landing_id} src={peer_ip} sport={peer_port} payload={text}",
                    flush=True,
                )
                reply = f"LANDING={landing_id} SRC={peer_ip} SPORT={peer_port} ECHO={text}\n"
                self.wfile.write(reply.encode("utf-8"))
                self.wfile.flush()

    return LandingHandler


class ReuseThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    srv = ReuseThreadingTCPServer((args.listen, args.port), make_handler(args.id))
    srv.serve_forever()


if __name__ == "__main__":
    main()
