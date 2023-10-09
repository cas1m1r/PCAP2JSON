from pcapper import CAP


def get_dest_ips(events):
    dest = []
    for event in events:
        dest.append(event['destination'])
    return dest


def get_source_ips(events):
    sources = []
    for event in events:
        source = event['source']
        sources.append(source)
    return sources


def main():
    f = "captures\\sample.pcapng"
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        f = sys.argv[1]    
    all_cap = CAP(f)
    all_cap.save()



if __name__ == '__main__':
    main()