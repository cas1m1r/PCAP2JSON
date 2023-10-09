# PCAP2JSON
Basic library for converting PCAP files into JSON files. Idea is that ML code is already well suited for parsing JSON, so make it easier to feed a PCAP to ML code.

# Dependencies
  * pyshark
  * tqdm

# Usage
```python
capture = CAP('example.pcap')
capture.save()
```
