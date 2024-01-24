#opfile

barrystyle 16062023

protocol version (00)
```
offset 0-3     |   magic bytes 'lynx' (4b)
offset 4       |   version byte (1b)
offset 5-20    |   uuid (16b)
offset 21-22   |   chunklen (2b)
offset 23-38   |   checksum (16b)
offset 39-42   |   chunknum (4b)
offset 43-46   |   chunktotal (4b)
offset 47-     |   data
```
