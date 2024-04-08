from urllib.parse import urlparse
import whois

def aname_check(anames):
    for aname in anames:
        print(whois.whois(aname['address']).text)

    #print(whois.whois('google.com'))
    return(whois.whois('google.com'))




