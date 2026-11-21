"""Local CLI helpers for payload previews and the loopback lab; no target scanning."""
import argparse, json, time
from .payloads import GENERATORS, generate
from .lab import LocalTelemetryLab

def main(argv=None):
    parser=argparse.ArgumentParser(prog="telemetry-scanner")
    sub=parser.add_subparsers(dest="command",required=True)
    p=sub.add_parser("payload",help="Generate a local-only dry-run payload preview")
    p.add_argument("protocol",choices=sorted(GENERATORS))
    p.add_argument("--max-bytes",type=int,default=65536)
    lab=sub.add_parser("lab",help="Start the private localhost telemetry test collector")
    lab.add_argument("--port",type=int,default=8080)
    lab.add_argument("--token",default="")
    args=parser.parse_args(argv)
    if args.command=="payload":
        print(json.dumps(generate(args.protocol,max_bytes=args.max_bytes).preview(),indent=2)); return 0
    collector=LocalTelemetryLab(token=args.token).start(args.port)
    print(f"Local telemetry lab listening at {collector.base_url}; press Ctrl+C to stop")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: collector.stop()
    return 0
if __name__=="__main__": raise SystemExit(main())
