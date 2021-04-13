import os
import boto3
import logging
import colorlog
import argparse
from pprint import pprint


# global vars
#############
logger = None
args = None
#############


def get_slash_set_path(path):
    try:
        slash = '/'
        if path and path != '':
            if os.name == 'nt':
                slash = '\\'
                path = path.replace('/', slash)
            else:
                path = path.replace('\\', slash)
    except Exception as e:
        logger.error(f"Exception {e} occurred in get_slash_set_path() for path {path}...")
    logger.info(f"get_slash_set_path() finished successfully for path {path}...")
    return path


def create_log_file(log_file_name):
    with open(log_file_name, 'w') as o: pass


def setup_logger(log_fmt="%(log_color)s%(asctime)s:%(levelname)s:%(message)s", log_file_name=".output.log", level='DEBUG'):

    # a new log file is created each time.
    # no space issues are caused.
    create_log_file(log_file_name)

    formatter = colorlog.ColoredFormatter(
        log_fmt,
        datefmt='%DT%H:%M:%SZ'
    )

    logger = logging.getLogger()

    handler2 = logging.FileHandler(log_file_name)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(handler2)
    logger.setLevel(level)

    return logger


def setup_args():
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-s', '--serial_number', metavar='<serial_number>', type=str, help='MFA device serial number. Eg: arn:aws:iam::112233445566:mfa/user')
    parser.add_argument('-t', '--token_code', metavar='<token_code>', type=str, help='MFA token. Eg: 123456')
    parser.add_argument('-d', '--duration_seconds', metavar='<duration_seconds>', type=int, default='129600', help='Duration for which the child profile will be valid for in seconds. Eg: Default is 129600')
    parser.add_argument('-p', '--aws_creds_file', metavar='<aws_creds_file>', type=str, default='~/.aws/credentials', help='Path to aws credentials file. Eg: Default is ~/.aws/credentials')
    parser.add_argument('-pp', '--parent_profile', metavar='<parent_profile>', type=str, help='Profile that will be used to generate the token. Eg: parent_profile')
    parser.add_argument('-ppr', '--parent_profile_region', metavar='<parent_profile_region>', type=str, default='us-east-1', help='Region of the profile that will be used to generate the token. Eg: Default is us-east-1')
    parser.add_argument('-cp', '--child_profile', metavar='<child_profile>', type=str, help='Profile that will be created & updated using the parent profile creds. Eg: child_profile')
    parser.add_argument('-v', '--verbosity', metavar='<verbosity>', type=str, default='DEBUG', help='Verbosity level of the script. Eg: SUCCESS|INFO|WARN|ERROR|DEBUG')
    parser.add_argument('-tg', '--testing', dest='testing', action='store_true', help='Switch for testing. Default "False". If testing, output file will be created but the STS token will not be generating any results. Eg: -t or --testing.')
    logger.info('Arguments parsed successfully...')
    return parser.parse_args()


def initialize_g_vars():
    global logger, args
    logger = setup_logger()
    args = setup_args()
    logger.setLevel(args.verbosity)
    args.aws_creds_file = get_slash_set_path(args.aws_creds_file)
    args.child_profile = '[{}]'.format(args.child_profile)


def load_parent_profile(parent_profile, parent_profile_region):
    aws_client = boto3.Session(profile_name=parent_profile).client('sts', region_name=parent_profile_region)
    return aws_client


def generate_child_profile_creds(aws_client, duration_seconds, serial_number, token_code, testing=False):
    ret = None
    if not testing:
        response = aws_client.get_session_token(
            DurationSeconds=int(duration_seconds),
            SerialNumber=serial_number,
            TokenCode=str(token_code)
        )
        if response and 'Credentials' in response:
            logger.info('Found credentials:')
            ret = response.get('Credentials')
            logger.info('Returning credentials:')
            pprint(ret)
    # when testing is True, generate test creds
    else:
        logger.info('Generating test credentials...')
        ret = {'AccessKeyId': 'Test Access Key',
                'Expiration': 'Test Expiration Time',
                'SecretAccessKey': 'Test Secret Key',
                'SessionToken': 'Test Session Token'}
        logger.info('Printing test creds...')
        pprint(ret)
    return ret


def read_creds_file(aws_creds_file):
    read_results = None
    with open(aws_creds_file) as f:
        read_results = f.readlines()
    logger.debug('Print creds file after reading...')
    pprint(read_results)
    return read_results


def find_child_profile_in_creds_file(aws_creds_file, child_profile):
    is_child_profile_in_creds_file = False
    read_results = None
    read_results = read_creds_file(aws_creds_file)
    logger.debug('Printing child_profile {}'.format(child_profile))
    for idx, line in enumerate(read_results):
        logger.debug('Checking existence of child_profile {} in {} ({})...'.format(child_profile, line, idx))
        if child_profile in line:
            logger.info('Found child profile in creds file line {}...'.format(idx+1))
            is_child_profile_in_creds_file = True
            break
    return is_child_profile_in_creds_file, read_results


def rewrite_aws_creds_file(aws_creds_file, read_results):
    with open(aws_creds_file, 'w') as o:
        for line in read_results:
            o.write(line)


def main():
    try:
        initialize_g_vars()
        aws_client = load_parent_profile(args.parent_profile, args.parent_profile_region)
        child_creds = generate_child_profile_creds(aws_client, args.duration_seconds, args.serial_number, args.token_code, testing=args.testing)
        is_child_profile_in_creds_file, read_results = find_child_profile_in_creds_file(args.aws_creds_file, args.child_profile)
        if is_child_profile_in_creds_file:
            logger.info('Found child profile in creds file...')
            for idx, result in enumerate(read_results):
                if args.child_profile in result:
                    logger.info('Found child profile in creds file at line {}...'.format(idx))
                    # end = len(read_results)
                    # if idx + 4 < len(read_results): end = idx+4 
                    for idx2, child_profile_line in enumerate(read_results[idx+1:idx+4]):
                        if 'aws_access_key_id' in child_profile_line:
                            read_results[idx+1+idx2] = 'aws_access_key_id = {}\n'.format(child_creds.get('AccessKeyId'))
                        if 'aws_secret_access_key' in child_profile_line:
                            read_results[idx+1+idx2] = 'aws_secret_access_key = {}\n'.format(child_creds.get('SecretAccessKey'))
                        if 'aws_session_token' in child_profile_line:
                            read_results[idx+1+idx2] = 'aws_session_token = {}\n'.format(child_creds.get('SessionToken'))
            logger.debug('Printing read_results when child profile is present:')
            pprint(read_results)
            rewrite_aws_creds_file(args.aws_creds_file, read_results)
        else:
            if read_results[-1][-1] != '\n': read_results.append('\n')
            child_profile_list = ['\n{}\n'.format(args.child_profile), 'aws_access_key_id = {}\n'.format(child_creds.get('AccessKeyId')), 'aws_secret_access_key = {}\n'.format(child_creds.get('SecretAccessKey')), 'aws_session_token = {}\n'.format(child_creds.get('SessionToken'))]
            read_results += child_profile_list
            rewrite_aws_creds_file(args.aws_creds_file, read_results)
    except Exception as e:
        logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))


# main flow of the program
##########################
if __name__ == '__main__':
    main()
##########################