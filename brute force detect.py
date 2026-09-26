import csv
from datetime import datetime


def readlogs():
    with open("brute_force_logs.csv", "r") as f:
        content = csv.DictReader(f)
        logs = []

        for line in content:
            logs.append(line)

        return logs


def analyze_logs(logs):

    total_events = 0

    failed_by_ip = {}
    failed_by_user = {}

    threshold = 10

    failed_timestamps = {}
    successful_login = {}

    # ==========================================
    # READ AND ORGANIZE LOGS
    # ==========================================

    for line in logs:

        total_events += 1

        timestamp = datetime.strptime(
            line["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        if line["result"] == "failed":

            ip = line["src_ip"]
            user = line["username"]

            # Count failures by IP
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

            # Count failures by user
            failed_by_user[user] = failed_by_user.get(user, 0) + 1

            # Store failed timestamps
            key = (ip, user)

            if key not in failed_timestamps:
                failed_timestamps[key] = []

            failed_timestamps[key].append(timestamp)

        elif line["result"] == "success":

            ip = line["src_ip"]
            user = line["username"]

            # Store successful login timestamps
            key = (ip, user)

            if key not in successful_login:
                successful_login[key] = []

            successful_login[key].append(timestamp)

    # ==========================================
    # BASIC STATISTICS
    # ==========================================

    print("Total events:", total_events)

    print("\nFailed attempts by IP:")

    for ip, count in failed_by_ip.items():
        print(f"  {ip}: {count}")

    print("\nFailed attempts by user:")

    for user, count in failed_by_user.items():
        print(f"  {user}: {count}")

    # ==========================================
    # FAILED TIMESTAMPS
    # ==========================================

    print("\nFailed timestamps:")

    for key, timestamps in failed_timestamps.items():

        ip, user = key

        print(f"\nIP: {ip}")
        print(f"User: {user}")

        for timestamp in timestamps:
            print(f"  {timestamp}")

    # ==========================================
    # SUCCESSFUL LOGINS
    # ==========================================

    print("\nSuccessful timestamps:")

    for key, timestamps in successful_login.items():

        ip, user = key

        print(f"\nIP: {ip}")
        print(f"User: {user}")

        for timestamp in timestamps:
            print(f"  {timestamp}")

    # ==========================================
    # TIME WINDOW BRUTE FORCE DETECTION
    # ==========================================

    print("\nTime Window Alert:")

    window = 60
    window_threshold = 5

    for key, timestamps in failed_timestamps.items():

        ip, user = key

        timestamps.sort()

        for i in range(len(timestamps)):

            count = 1

            for j in range(i + 1, len(timestamps)):

                difference = (
                    timestamps[j] - timestamps[i]
                ).total_seconds()

                if difference <= window:
                    count += 1
                else:
                    break

            if count >= window_threshold:

                print(
                    f"ALERT: IP {ip} and User {user} "
                    f"have {count} failed attempts "
                    f"within {window} seconds."
                )

                break

    # ==========================================
    # BRUTE FORCE -> SUCCESS CORRELATION
    # ==========================================

    print("\nBrute Force -> Successful Login:")

    correlation_window = 60
    correlation_threshold = 5

    for key, success_times in successful_login.items():

        ip, user = key

        # Get failures for the same IP + user
        failure_times = failed_timestamps.get(key, [])

        for success_time in success_times:

            failure_count = 0

            for failure_time in failure_times:

                # Calculate time difference
                difference = (
                    success_time - failure_time
                ).total_seconds()

                # Failure must happen BEFORE success
                # and within 60 seconds
                if 0 <= difference <= correlation_window:

                    failure_count += 1

            # Generate alert
            if failure_count >= correlation_threshold:

                print("\n🚨 BRUTE FORCE -> SUCCESS")

                print(f"IP: {ip}")
                print(f"User: {user}")
                print(f"Failed attempts: {failure_count}")
                print(f"Successful login: {success_time}")

                print(
                    f"Failures occurred within "
                    f"{correlation_window} seconds before success."
                )


def main():

    logs = readlogs()

    analyze_logs(logs)


if __name__ == "__main__":
    main()
