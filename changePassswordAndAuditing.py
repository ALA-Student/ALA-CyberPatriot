
import sys, os, subprocess

#subprocess.run("secedit /export /cfg C:\temp.cfg")

lines = []

with open('dogo') as f:
    content = f.readlines()
    
for line in content:
    if line == "PasswordComplexity = 0\n":
        line = "PasswordComplexity = 1\n"
    lines.append(line)
    newFile = open('newFile', 'w')
    
for line in lines:
    newFile.write("%s\n" % line)
