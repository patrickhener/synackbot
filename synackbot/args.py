import argparse

parser = argparse.ArgumentParser(
	description="Synack API request and bot implementation"
)

parser.add_argument(
	"-v", "--version", action='version', version="Synack API bot v1.0"
)

oneshot_group = parser.add_mutually_exclusive_group()

oneshot_group.add_argument(
	"-H", "--hydra", dest="HYDRA", default=False, action="store_true", help="Pull hydra results (combined with 'codename')"
)

oneshot_group.add_argument(
	"-a", "--analytics", dest="ANALYTICS", default=False, action="store_true", help="Download analytics (combined with 'codename')"
)

oneshot_group.add_argument(
	"-s", "--scope", dest="SCOPE", default=False, action="store_true", help="Download scope (combined with 'codename')"
)

oneshot_group.add_argument(
"-t", "--target", dest="TARGET", default=False, action="store_true", help="Reads current target or sets it when combined with 'codename'"
)

oneshot_group.add_argument(
"-T", "--transactions", dest="TRANSACTIONS", default=False, action="store_true", help="Display transaction overview"
)

parser.add_argument(
	"-c", "--codename", dest="CODENAME", default=None, type=str, help="Target codename"
)

def parse_args():
	args = parser.parse_args()

	return args