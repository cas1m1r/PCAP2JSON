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
# Future Improvements 
This is the alternate approach I came up with. First was to parse each packet based on protocol type, but this creates a somewhat complicated structure to maintain. 
Using a dynamically evaluated expression to decode packet fields allowed me to remove all of these classes and create a single function (at the cost of performance). 
Revisiting previous or new approaches that are more efficient will be a next step. 
