# JavaID
java source code danger function identify prog

# How does it work?
 JavaID identify some dangerous functions in java source code by way of regular matching.
 
 For further details, check out the source code on the main site, github.com/Cryin/JavaID.
 
# What does it identify?

 ```
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
    "Socket",
    "URL",
    "ImageIO",
    "HttpURLConnection",
    "OkHttpClient" 
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
 ```
 
 and so on...
 
 Also you can add function id with regexp.xml!
 
# How do I use it?

 Usage: python javaid.py -d dir
 
# Questions?

 contact me :)
