import sys
import argparse
import time

from cogsoc_behav import (
    start_cicflow_capture,
    start_filebeat,
    apply_detection_config,
    cleanup_and_exit,
    parse_duration_minutes
)

def main():
    parser = argparse.ArgumentParser(description='CogSOC Traffic Capture Engine')
    parser.add_argument('--interface', type=str, default=None)
    parser.add_argument('--duration-minutes', type=str, default=None)
    parser.add_argument('--sensitivity', type=str, default='medium')
    args = parser.parse_args()

    apply_detection_config(args)
    duration_minutes = parse_duration_minutes(args.duration_minutes)

    print("=" * 65)
    print("  CogSOC — Independent Traffic Capture Engine")
    print("=" * 65)

    try:
        start_cicflow_capture(
            stop_after_seconds=(duration_minutes * 60 if duration_minutes else None)
        )
    except Exception as e:
        print(f"[CAPTURE] Warning: CICFlowMeter capture could not start: {e}")

    try:
        start_filebeat()
    except Exception as e:
        print(f"[FILEBEAT] Warning: Filebeat could not start: {e}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup_and_exit()

if __name__ == "__main__":
    main()
