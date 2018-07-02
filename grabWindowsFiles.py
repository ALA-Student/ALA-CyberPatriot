
import sys, os, time

defaultFiles = []

mediaFiles = []

exts = (".avi", ".mp3", ".mp4", ".vob", ".bat", ".jpg", ".gif", ".bmp", ".mpg",)

rootdir = """C:\""""

for root, subdirs, files in os.walk(rootdir):
    for f in files:
        for x in exts:
            if "." + x in f:
                mediaFiles.append()
