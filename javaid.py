#!/usr/bin/env python
# -*- coding:utf-8 -*-
# java source danger function identify prog
# Auth by Cryin'

import re
import os
import optparse
import sys
from lxml.html import etree

'''
XXE:
    "SAXReader",
    "DocumentBuilder",
    "XMLStreamReader",
    "SAXBuilder",
    "SAXParser",
    "XMLReader",
    "SAXSource",
    "TransformerFactory",
    "SAXTransformerFactory",
    "SchemaFactory",
    "Unmarshaller",
    "XPathExpression"

JavaObjectDeserialization:
    "readObject",
    "readUnshared",
    "Yaml.load",
    "fromXML",
    "ObjectMapper.readValue",
    "JSON.parseObject"
SSRF:
    "HttpClient",
    "URL",
    "HttpURLConnection"
FILE:
    "MultipartFile",
    "createNewFile",
    "FileInputStream"
Autobinding:
    "@SessionAttributes",
    "@ModelAttribute"
URL-Redirect:
    "sendRedirect",
    "forward",
    "setHeader"
EXEC:
    "getRuntime.exec",
    "ProcessBuilder.start",
    "GroovyShell.evaluate"

 '''

class javaid(object):
    def __init__(self,dir):

        self._function = ''
        self._fpanttern = ''
        self._line = 0
        self._dir = dir
        self._filename = ''
        self._vultype = ''
    def _run(self):
        try:
            self.banner()
            self.handlePath(self._dir)
            print "[-]【JavaID】identify danger function Finished!"    
        except:
            raise

    def report_id(self,vul):
        print "[+]【"+vul+"】identify danger function ["+self._function+"] in file ["+self._filename+"]"

    def report_line(self):
        print " --> [+] on line : "+ str(self._line)

    def handlePath(self, path):
        dirs = os.listdir(path) 

        for d in dirs:
            subpath = os.path.join(path, d) 
            if os.path.isfile(subpath):
                if os.path.splitext(subpath)[1] == '.java' or os.path.splitext(subpath)[1] == '.xml':
                    self._filename =subpath
                    self.handleFile(subpath)  
            else:
                self.handlePath(subpath) 
    
    def handleFile(self, fileName):
        #print 'begin read file:' + fileName
        f = open(fileName, 'r') 
        self._line = 0
        content = f.read()
        content=self.remove_comment(content)
        self.check_regexp(content)

        f.close() 
        #print 'read over file:' + fileName
        #print '------------------------'
    def function_search_line(self):
        fl = open(self._filename, 'r') 
        self._line =0
        importregexp="import\s[^;]*;"
        #print "function_search_line"+self._filename
        while True:
            line = fl.readline() 
            if not line:  
                #print "flclose"+str(self._line)
                break

            self._line += 1
            #print line
            exp_pattern = re.compile(importregexp)
            if exp_pattern.search(line):
                continue
            if self._function in line:
                #print 'find danger function on line :' + str(line)
                self.report_line()
                continue
        fl.close()
    def regexp_search(self,rule_dom,content):

        regmatch_dom = rule_dom[0].xpath("regmatch")
        regexp_doms = regmatch_dom[0].xpath("regexp") if regmatch_dom != None else []
        for regexp_dom in regexp_doms:
                exp_pattern = re.compile(regexp_dom.text)
                if exp_pattern.search(content):
                    #print "identify sfunction is : "+self._function
                    self.report_id(self._vultype)
                    self.function_search_line()

        return True
    def check_regexp(self, content):
        if not content:
            return
        self._xmlstr_dom = etree.parse('regexp.xml')
        javaid_doms = self._xmlstr_dom.xpath("javaid")
        for javaid_dom in javaid_doms:
            self._vultype =javaid_dom.get("vultype")
            #print "vul_type "+self._vultype
            function_doms = javaid_dom.xpath("function")
            for function_dom in function_doms:
                rule_dom = function_dom.xpath("rule")
                self._function =rule_dom[0].get("name")
                self.regexp_search(rule_dom,content)
                #print "check_regexp search ..."
        return True
    def remove_comment(self,content):
        return content
    def banner(self):
        print "[-]【JavaID】 Danger function identify tool"
if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/java/demo)')
    parser.add_option('-d', '--dir', dest = 'dir', type = 'string', help = 'source code file dir')

    (options, args) = parser.parse_args()

    if options.dir == None or options.dir == "":
        parser.print_help()
        sys.exit()
    dir =options.dir
    javaidentify = javaid(dir)
    javaidentify._run()

