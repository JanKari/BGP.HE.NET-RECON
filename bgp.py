import argparse, csv, json, os, pprint, Queue, random, requests, selenium, string, sys, time
from datetime import datetime
from urllib import unquote_plus as urlencode

### 3RD PARTY IMPORTS
try:
	from colorama import Fore, Style
except:
	print "[ERROR] Please install the \"colorama\" module!"
	sys.exit(1)

try:
	from bs4 import BeautifulSoup
except:
	print_error("Please install BeautifulSoup!")
	sys.exit(1)

try:
	from selenium.webdriver.common.by import By
	from selenium.webdriver.support.ui import WebDriverWait
	from selenium.webdriver.support import expected_conditions as EC
	from selenium.webdriver.remote.command import Command
	### CLASS FUNCTION OVERIDE
	class myChrome(selenium.webdriver.Chrome):
		def get(self, url, chromeBrowser, verbose):
			try:
				self.execute(Command.GET, {'url': url})
			except:
				if proxySet:
					if verbose:
						print_warning("Current proxy is too slow, updating proxy...")
					chromeBrowser = setNewProxy(chromeBrowser, verbose)
					chromeBrowser = chromeBrowser.get(url, chromeBrowser, verbose)
			return chromeBrowser
except:
	print_error("Please install Selenium and Chrome web driver!")
	sys.exit(1)

### STATIC GLOBAL VARIABLES
VALIDCHARS       = string.ascii_letters + string.digits + ' '
BASEURL          = "https://bgp.he.net"
PROXY_LIST_SLEEP = 60
RESPONSE_TIMEOUT = 15
USERAGENTS       = [ua.strip() for ua in open("user-agents.txt").readlines()]

### DYNAMIC GLOBAL VARIABLES
errorCounter = 0
proxySet     = False
usedProxies  = []

### CORE FUNCTIONS
def convertToValidChars(companyName):
	return ''.join([c for c in companyName if c in VALIDCHARS])

def getIPLocation(userAgent, IP):
	url = "https://ipinfo.io/%s/json" % IP
	headers = {"User-Agent": "%s" % userAgent, "Accept": "application/json;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
	response = requests.get(url, headers=headers)
	data = json.loads(response.text)
	country=data['country']
	city = data['city']
	if not city:
		city = "Unknown City"
	return "%s, %s" % (city, country)

def getLinks(table, targetCompany):
	targetCompanyQueryLinks = {}
	rows                    = table.find_all('tr')
	for row in rows:
		cols = row.find_all('td')
		if (len(cols) == 2) and (targetCompany.lower() == convertToValidChars(cols[1].text.lower())):
			if (cols[1].text in targetCompanyQueryLinks.keys()) and (cols[0].find_all('a')[0]['href'] not in targetCompanyQueryLinks[cols[1].text]["links"]):
				targetCompanyQueryLinks[cols[1].text]["links"].append(cols[0].find_all('a')[0]['href'])
			else:
				targetCompanyQueryLinks[cols[1].text] = {"links" : [cols[0].find_all('a')[0]['href']]}
	return targetCompanyQueryLinks

def getAllProxies(userAgent, verbose=True):
	if verbose:
		print_warning("Fetching new proxy list...")
	HTTPProxies = getHTTPProxies(userAgent)
	socksProxies = getSOCKSProxies(userAgent)
	newProxies = HTTPProxies or socksProxies
	if verbose and newProxies:
		print_success("Successfully retreived proxy list!")
	return newProxies

def getHTTPProxies(userAgent):
	global proxyQ
	newProxies = False
	url = "https://free-proxy-list.net/"
	headers = {"User-Agent": "%s" % userAgent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
	response = requests.get(url, headers=headers)

	soup = BeautifulSoup(response.text, "html.parser")
	for row in soup.find("table").tbody.findAll("tr"):
		allColumns = row.findAll("td")
		IP = allColumns[0].text
		port = allColumns[1].text
		https = allColumns[6].text
		lastChecked = allColumns[-1].text
		if (lastChecked.split()[1] in ["second", "seconds", "minute"]) and (https == "yes") and (IP not in usedProxies):
			newProxies = True
			proxyQ.put(("http",IP,port))
	return newProxies

def getSOCKSProxies(userAgent):
	global proxyQ
	newProxies = False
	url = "https://www.socks-proxy.net/"
	headers = {"User-Agent": "%s" % userAgent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
	response = requests.get(url, headers=headers)

	soup = BeautifulSoup(response.text, "html.parser")
	for row in soup.find("table").tbody.findAll("tr"):
		allColumns = row.findAll("td")
		IP = allColumns[0].text
		port = allColumns[1].text
		version = allColumns[4].text.lower()
		lastChecked = allColumns[-1].text
		if (lastChecked.split()[1] in ["second", "seconds", "minute"]) and (IP not in usedProxies):
			newProxies = True
			proxyQ.put((version,IP,port))
	return newProxies

def parseASNumber(HTML,targetCompany):
	discoveredIPv4s = []
	discoveredIPv6s = []
	discoveredLinks = []
	discoveredWHOIS = []
	soup            = BeautifulSoup(HTML, "html.parser")
	discoveredWHOIS = [[l.strip().split('\n') for l in soup.find("div", {"id":"whois"}).text.split('\n\n') if len(l) and len(''.join(l.strip().split('\n')))]]
	try:
		IPv4andLinkData = soup.find("div", {"id":"prefixes"}).find("table")
		rows            = IPv4andLinkData.find_all('tr')
		for row in rows:
			cols = row.find_all('td')
			if len(cols) == 2:
				if convertToValidChars(cols[1].text.strip().lower()) == targetCompany.lower():
					if cols[0].text.strip() not in discoveredIPv4s:
						discoveredIPv4s.append(cols[0].text.strip())
					if cols[0].find('a')['href'] not in discoveredLinks:
						discoveredLinks.append(cols[0].find('a')['href'])
	except:
		pass
	try:
		IPv6andLinkData = soup.find("div", {"id":"prefixes6"}).find("table")
		rows            = IPv6andLinkData.find_all('tr')
		for row in rows:
			cols = row.find_all('td')
			if len(cols) == 2:
				if convertToValidChars(cols[1].text.strip().lower()) == targetCompany.lower():
					if cols[0].text.strip() not in discoveredIPv6s:
						discoveredIPv6s.append(cols[0].text.strip())
					if cols[0].find('a')['href'] not in discoveredLinks:
						discoveredLinks.append(cols[0].find('a')['href'])
	except:
		pass
	return (discoveredIPv4s, discoveredIPv6s, discoveredLinks, discoveredWHOIS)

def parseNetwork(HTML,targetCompany):
	discoveredIPv4s       = []
	discoveredIPv6s       = []
	discoveredLinks       = []
	discoveredDomainNames = []
	discoveredWHOIS       = []
	soup                  = BeautifulSoup(HTML, "html.parser")
	discoveredWHOIS       = [[l.strip().split('\n') for l in soup.find("div", {"id":"whois"}).text.split('\n\n') if len(l) and len(''.join(l.strip().split('\n')))]]
	IPandLinkData         = soup.find("div", {"id":"netinfo"}).find("table")
	rows                  = IPandLinkData.find_all('tr')
	for row in rows:
		cols = row.find_all('td')
		if len(cols) == 3:
			if convertToValidChars(cols[2].text.strip().lower()) == targetCompany.lower():
				if len(cols[1].text.strip().split(':')) == 1:
					if cols[1].text.strip() not in discoveredIPv4s:
						discoveredIPv4s.append(cols[1].text.strip())
				elif len(cols[1].text.strip().split(':')) > 1:
					if cols[1].text.strip() not in discoveredIPv6s:
						discoveredIPv6s.append(cols[1].text.strip())
				if cols[0].find('a')['href'] not in discoveredLinks:
					discoveredLinks.append(cols[0].find('a')['href'])
				if cols[1].find('a')['href'] not in discoveredLinks:
					discoveredLinks.append(cols[1].find('a')['href'])
	domainNameData = soup.find("div", {"id":"dns"}).find("table")
	try:
		rows = domainNameData.find_all('tr')
		for row in rows:
			cols = row.find_all('td')
	 		if len(cols) == 3:
				for domainName in cols[1].text.strip().split(', '):
					if len(domainName) and domainName not in discoveredDomainNames:
						discoveredDomainNames.append(domainName)
				for domainName in cols[2].text.strip().split(', '):
					if len(domainName) and domainName not in discoveredDomainNames:
						discoveredDomainNames.append(domainName)
	except:
		pass
	return (discoveredIPv4s, discoveredIPv6s, discoveredLinks, discoveredDomainNames, discoveredWHOIS)

def print_error(msg):
	print "%s[ERROR]%s %s" % (Fore.RED,Style.RESET_ALL,msg)

def print_success(msg):
	print "%s[w00t]%s %s" % (Fore.GREEN,Style.RESET_ALL,msg)

def print_warning(msg):
	formattedDate = datetime.now().strftime("%Y-%m-%d %I:%M%p")
	print "%s[%s]%s %s" % (Fore.YELLOW,formattedDate,Style.RESET_ALL,msg)

def queryBGP(targetCompany, userAgent, debug=False, verbose=True):
	global defaultChromeOptions
	queryUrl = BASEURL + "/search?search%%5Bsearch%%5D=%s&commit=Search" % urlencode(targetCompany)
	ChromeOptions = selenium.webdriver.ChromeOptions()
	if not debug:
		ChromeOptions.add_argument('headless')
	defaultChromeOptions = ChromeOptions
	ChromeOptions.add_argument("--user-agent=%s" % userAgent)
	chromeBrowser = myChrome(chrome_options=ChromeOptions)
	chromeBrowser.set_page_load_timeout(RESPONSE_TIMEOUT)
	chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
	chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, "search", verbose)
	soup              = BeautifulSoup(chromeBrowser.page_source, "html.parser")
	targetCompanyData = getLinks(soup.find_all("table")[0], targetCompany)
	for companyName in targetCompanyData.keys():
		targetCompanyData[companyName]["domainNames"]   = []
		targetCompanyData[companyName]["IPv4Addresses"] = []
		targetCompanyData[companyName]["IPv6Addresses"] = []
		targetCompanyData[companyName]["parsedLinks"]   = []
		targetCompanyData[companyName]["WHOIS"]         = []
	for companyName,data in targetCompanyData.iteritems():
		while 1:
			for link in data["links"]:
				if link not in data["parsedLinks"]:
					queryUrl = BASEURL+link
					if link.upper().startswith("/AS"):
						chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
						chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, "whois", verbose)
						(discoveredIPv4s, discoveredIPv6s, discoveredLinks, discoveredWHOIS) = parseASNumber(chromeBrowser.page_source,targetCompany)
						data["parsedLinks"].append(link)
						for IPv4 in discoveredIPv4s:
							if IPv4 not in data["IPv4Addresses"]:
								data["IPv4Addresses"].append(IPv4)
						for IPv6 in discoveredIPv6s:
							if IPv6 not in data["IPv6Addresses"]:
								data["IPv6Addresses"].append(IPv6)
						for newLink in discoveredLinks:
							if newLink not in data["links"]:
								data["links"].append(newLink)
						for WHOIS in discoveredWHOIS:
							if WHOIS not in data["WHOIS"]:
								data["WHOIS"].append(WHOIS)
					if link.lower().startswith("/net"):
						chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
						chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, "whois", verbose)
						(discoveredIPv4s, discoveredIPv6s, discoveredLinks, discoveredDomainNames, discoveredWHOIS) = parseNetwork(chromeBrowser.page_source,targetCompany)
						data["parsedLinks"].append(link)
						for IPv4 in discoveredIPv4s:
							if IPv4 not in data["IPv4Addresses"]:
								data["IPv4Addresses"].append(IPv4)
						for IPv6 in discoveredIPv6s:
							if IPv6 not in data["IPv6Addresses"]:
								data["IPv6Addresses"].append(IPv6)
						for newLink in discoveredLinks:
							if newLink not in data["links"]:
								data["links"].append(newLink)
						for domainName in discoveredDomainNames:
							if domainName not in data["domainNames"]:
								data["domainNames"].append(domainName)
						for WHOIS in discoveredWHOIS:
							if WHOIS not in data["WHOIS"]:
								data["WHOIS"].append(WHOIS)
			if sorted(data["links"]) == sorted(data["parsedLinks"]):
				break
	chromeBrowser.quit()
	return targetCompanyData

def randomUserAgent(verbose):
	newUserAgent = USERAGENTS[random.randint(0,len(USERAGENTS)-1)]
	if verbose:
		print_warning("Using \"%s\" as the User-Agent..." % newUserAgent)
	return newUserAgent

def setNewProxy(chromeBrowser, verbose):
	global proxySet, usedProxies
	newUserAgent = randomUserAgent(verbose)
	if proxyQ.empty():
		if verbose:
			print_warning("Empty proxy list...")
		while not getAllProxies(newUserAgent, verbose):
			if verbose:
				print_warning("Couldn't find any recently verified proxies... Waiting %.2f minute(s) then refreshing..." % (PROXY_LIST_SLEEP/60.0))
				time.sleep(PROXY_LIST_SLEEP)
			newUserAgent = randomUserAgent(verbose)
	chromeBrowser.quit()
	newProxyData  = proxyQ.get()
	newProxyProto = newProxyData[0]
	newProxyIP    = newProxyData[1]
	newProxyPort  = newProxyData[2]
	usedProxies.append(newProxyIP)
	newProxy      = "%s://%s:%s" % (newProxyProto, newProxyIP, newProxyPort)
	chromeOptions = defaultChromeOptions
	chromeOptions.add_argument("--proxy-server=%s" % newProxy)
	chromeOptions.add_argument("--user-agent=%s" % newUserAgent)
	chromeBrowser = myChrome(chrome_options=chromeOptions)
	proxySet = True
	if verbose:
		print_warning("Traffic is now routing through \"%s\" which is located in \"%s\"..." % (newProxyIP, getIPLocation(newUserAgent, newProxyIP)))
	chromeBrowser.set_page_load_timeout(RESPONSE_TIMEOUT)
	return chromeBrowser

def waitForWebResponse(queryUrl, chromeBrowser, userAgent, idName, verbose=True):
	global errorCounter
	while 1:
		try:
			responseTime = (chromeBrowser.execute_script("return window.performance.timing.responseStart") - chromeBrowser.execute_script("return window.performance.timing.navigationStart"))/1000.0
		except:
			responseTime = RESPONSE_TIMEOUT
		if (errorCounter >= 30) or (proxySet and responseTime <= 0.01) or (proxySet and responseTime >= RESPONSE_TIMEOUT):
			if verbose:
				print_warning("Current proxy has connectivity issues, updating proxy...")
			chromeBrowser = setNewProxy(chromeBrowser, verbose)
			chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
			chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, idName, verbose)
		elif "did not return any results" in chromeBrowser.page_source:
			print_error("Manually validate your target's name(s) on %s and try again with the correct name. Exiting..." % BASEURL)
			chromeBrowser.quit()
			sys.exit(1)
		elif "requires javascript and cookies to function. Please enable these in your browser." in chromeBrowser.page_source:
			if verbose:
				print_warning("You have been blocked at the application layer from querying %s... Bypassing..." % BASEURL)
			chromeBrowser.quit()
			if proxySet:
				chromeBrowser = setNewProxy(chromeBrowser, verbose)
			else:
				newUserAgent  = randomUserAgent(verbose)
				chromeOptions = defaultChromeOptions
				chromeOptions.add_argument("--user-agent=%s" % newUserAgent)
				chromeBrowser = myChrome(chrome_options=defaultChromeOptions)
				chromeBrowser.set_page_load_timeout(RESPONSE_TIMEOUT)
			chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
			chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, idName, verbose)
			if verbose:
				print_success("Successfully bypassed query restrictions!")
		elif "You have reached your query limit" in chromeBrowser.page_source:
			if verbose:
				print_warning("You have been blocked at the network layer from querying %s... Bypassing..." % BASEURL)
			chromeBrowser = setNewProxy(chromeBrowser, verbose)
			chromeBrowser = chromeBrowser.get(queryUrl, chromeBrowser, verbose)
			chromeBrowser = waitForWebResponse(queryUrl, chromeBrowser, userAgent, idName, verbose)
			if verbose:
				print_success("Successfully bypassed query restrictions!")
		try:
			WebDriverWait(chromeBrowser, 1).until(EC.presence_of_element_located((By.ID, idName)))
			errorCounter = 0
			return chromeBrowser
		except:
			errorCounter += 1
### MAIN
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("targetCompanyNames", help="target company names (e.g. \"Google, Inc.\" \"Google, LLC\" \"Google Access LLC\")", type=str, nargs='+')
	parser.add_argument("-d", "--debug", help="spawn Chrome browser in GUI mode", action='store_true')
	parser.add_argument("-v", "--verbose", help="print logging messages to STDOUT", action='store_true')
	args = parser.parse_args()

	userAgent = randomUserAgent(args.verbose)
	proxyQ = Queue.Queue()
	startTime = datetime.now()
	outputFileName = "%d-%d-%d_%d-%d-%d.csv" % (startTime.year, startTime.month, startTime.day, startTime.hour, startTime.minute, startTime.second)

	with open(outputFileName, 'wb') as csvfile:
		writer = csv.DictWriter(csvfile, fieldnames=['targetCompanyName', 'domainNames', 'IPv4Addresses', 'IPv6Addresses'])
		writer.writeheader()
		for targetCompanyName in args.targetCompanyNames:
			targetCompanyName = convertToValidChars(targetCompanyName)
			targetCompanyData = queryBGP(targetCompanyName, userAgent=userAgent, debug=args.debug, verbose=args.verbose)
			if not targetCompanyData:
				print_error("Manually validate your target's name(s) on %s and try again with the correct name. Exiting..." % BASEURL)
				sys.exit(1)
			for targetCompany in targetCompanyData.keys():
				writer.writerow({'targetCompanyName': targetCompany, 'domainNames': ', '.join(targetCompanyData[targetCompany]['domainNames']), 'IPv4Addresses': ', '.join(targetCompanyData[targetCompany]['IPv4Addresses']), 'IPv6Addresses': ', '.join(targetCompanyData[targetCompany]['IPv6Addresses'])})
	print_success("%s successfully written!" % outputFileName)
	if args.verbose: print_warning("Script completed in %s (H:MM:SS.MS)" % (datetime.now() - startTime))

