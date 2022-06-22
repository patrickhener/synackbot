import requests
import re
import json
import warnings
import operator
import datetime
import time
import pyotp

from tabulate import tabulate

from urllib.parse import urlparse
from netaddr import IPNetwork
from pathlib import Path

from synackbot.logging import log
from synackbot.static import URL_ANALYTICS_CATEGROIES, URL_ANALYTICS_CONNECTIONS, URL_ANALYTICS_SUBMISSION, URL_CLAIMED_AMOUNT, URL_REGISTERED_SUMMARY, URL_SCOPE_SUMMARY, URL_ACTIVATE_TARGET, URL_ASSESMENTS, URL_VULNERABILITIES, URL_DRAFTS, URL_UNREGISTERED_SLUGS, URL_PROFILE, URL_HYDRA, URL_PUBLISHED_MISSIONS, URL_NOTIFICATION_TOKEN, URL_NOTIFICATION_API, URL_TRANSACTIONS, URL_UNREAD_MESSAGE_COUNT
from synackbot.config import EMAIL,PASSWORD,LOGIN_WAIT,LOGIN_URL,AUTHY_SECRET,SESSION_TOKEN_PATH,NOTIFICATION_TOKEN_PATH,PROXY,PROXY_PORT

warnings.filterwarnings("ignore")

class Synack:
    codename = None
    def __init__(self):
        self.session = requests.Session()
        self.jsonResponse = []
        self.assessments = []
        self.ignore_slugs = []
        self.token = ""
        self.notificationToken = ""
        self.webheaders = {}
        self.email = EMAIL
        self.password = PASSWORD
        self.login_wait = LOGIN_WAIT
        self.login_url = LOGIN_URL
        self.authySecret = AUTHY_SECRET
        self.sessionTokenPath = SESSION_TOKEN_PATH
        self.notificationTokenPath = NOTIFICATION_TOKEN_PATH
        self.proxyport = PROXY_PORT
        self.Proxy = PROXY

#########
    def getAuthy(self):
        totp = pyotp.TOTP(self.authySecret)
        totp.digits = 7
        totp.interval = 10
        totp.issuer = "synack"
        return(totp.now())

## Get Synack platform session token ##
    def getSessionToken(self):
        if Path(self.sessionTokenPath).exists():
            with open(self.sessionTokenPath, "r") as f:
                self.token = f.readline()
            f.close()
            log.info("Reusing old session token")
        else:
            self.connectToPlatform()
        self.webheaders = {"Authorization": "Bearer " + self.token}
        response = self.try_requests("GET", URL_PROFILE, 10)
        profile = response.json()
        self.webheaders['user_id'] = profile['user_id']

#################################################
## Function to attempt requests multiple times ##
#################################################

    def try_requests(self, func, URL, times, extra=None):
        http_proxy  = "http://127.0.0.1:%d" % self.proxyport
        https_proxy = "http://127.0.0.1:%d" % self.proxyport
        proxyDict = {
            "http" : http_proxy,
            "https" : https_proxy
        }

        url = urlparse(URL)
        netloc = url.netloc
        platform = "platform.synack"

        if self.Proxy == True:
            for _ in range(times):
                try:
                    if func == "PUT":
                        putData = json.dumps({"listing_id": extra})
                        newHeaders = dict(self.webheaders)
                        newHeaders['Content-Type'] = "application/json"
                        response = self.session.put(URL, headers=newHeaders, data=putData, proxies=proxyDict, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "GET":
                        if extra == None:
                            response = self.session.get(URL, headers=self.webheaders, proxies=proxyDict, verify=False)
                            if response.status_code == 401 and platform in netloc:
                                self.connectToPlatform()
                                self.getSessionToken()
                            else:
                                return response
                        else:
                            parameters = {'page': extra}
                            response = self.session.get(URL, headers=self.webheaders, params=parameters, proxies=proxyDict, verify=False)
                            if response.status_code == 401 and platform in netloc:
                                self.connectToPlatform()
                                self.getSessionToken()
                            else:
                                return response
                    elif func == "POST":
                        response = self.session.post(URL, headers=self.webheaders, proxies=proxyDict, json=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "PATCH":
                        newHeaders = dict(self.webheaders)
                        newHeaders['Content-Type'] = "application/json"
                        # PATCH request does not support `json=` parameter
                        response = self.session.patch(URL, headers=newHeaders, proxies=proxyDict, data=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "DELETE":
                        response = self.session.delete(URL, headers=self.webheaders, proxies=proxyDict, json=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                except Exception as err:
                    last_err = err
            raise last_err
        else:
            for _ in range(times):
                try:
                    if func == "PUT":
                        putData = json.dumps({"listing_id": extra})
                        newHeaders = dict(self.webheaders)
                        newHeaders['Content-Type'] = "application/json"
                        response =self.session.put(URL, headers=newHeaders, data=putData, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "GET":
                        if extra == None:
                            response =self.session.get(URL, headers=self.webheaders, verify=False)
                            if response.status_code == 401 and platform in netloc:
                                self.connectToPlatform()
                                self.getSessionToken()
                            else:
                                return response
                        else:
                            parameters = {'page': extra}
                            response = self.session.get(URL, headers=self.webheaders, params=parameters, verify=False)
                            if response.status_code == 401 and platform in netloc:
                                self.connectToPlatform()
                                self.getSessionToken()
                            else:
                                return response
                    elif func == "POST":
                        response =  self.session.post(URL, headers=self.webheaders, json=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "PATCH":
                        # PATCH request does not support `json=` parameter
                        newHeaders = dict(self.webheaders)
                        newHeaders['Content-Type'] = "application/json"
                        response = self.session.request("PATCH", URL, headers=newHeaders, data=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    elif func == "DELETE":
                        response = self.session.delete(URL, headers=self.webheaders, json=extra, verify=False)
                        if response.status_code == 401 and platform in netloc:
                            self.connectToPlatform()
                            self.getSessionToken()
                        else:
                            return response
                    else:
                        raise ValueError("Choose a real HTTP method.")
                except Exception as err:
                    last_err = err
            raise last_err


####################################################
## Function to find all occurrences of nested key ##
####################################################

    def findkeys(self, node, kv):
        if isinstance(node, list):
            for i in node:
                for x in self.findkeys(i, kv):
                    yield x
        elif isinstance(node, dict):
            if kv in node:
                yield node[kv]
            for j in node.values():
                for x in self.findkeys(j, kv):
                    yield x

##############################################
## Returns a JSON of all registered targets ##
## This must be the first call after object ##
## instantiation - it populates the json    ##
##############################################
    def getAllTargets(self):
        self.jsonResponse.clear()
        try:
            response = self.try_requests("GET", URL_REGISTERED_SUMMARY, 10)
            self.jsonResponse[:] = response.json()
            return(response.status_code)
        except:
            return(-1)



########################################
## Returns a list of web or host target codenames
## that are (mission only / not mission only)
## category: web || host || RE || mobile || sourceCode || hardware
## mission_only: True || False
########################################
    def getCodenames(self, category, mission_only=False):
        categories = ("web application", "re", "mobile", "host", "source code","hardware")
        category = category.lower()
        if category == "web":
            category = "web application"
        if category == "re":
            category = "reverse engineering"
        if category == "sourcecode":
            category = "source code"
        if category not in categories:
            raise Exception("Invalid category.")
        targets = []
        for i in range (len(self.jsonResponse)):
            if mission_only == True:
                if self.jsonResponse[i]['vulnerability_discovery'] == False:
                    if self.jsonResponse[i]['category']['name'].lower() == category.lower():
                        targets.append(self.jsonResponse[i]['codename'])
                    else:
                        continue
                else:
                    continue
            elif mission_only == False:
                if self.jsonResponse[i]['vulnerability_discovery'] == True:
                    if self.jsonResponse[i]['category']['name'].lower() == category.lower():
                        targets.append(self.jsonResponse[i]['codename'])
                    else:
                        continue
                else:
                    continue
        return(targets)

#########################################
## This returns the "slug" of a target ##
## based on the codename ##
#########################################

    def getTargetID(self, codename):
        for i in range (len(self.jsonResponse)):
            if self.jsonResponse[i]['codename'].lower() == codename.lower():
                return(self.jsonResponse[i]['id'])

##################################
## This retuens the codemane of ##
## a target based on the slug   ##
##################################
    def getCodenameFromSlug(self, slug):
        for i in range(len(self.jsonResponse)):
            if self.jsonResponse[i]['id'].lower() == slug.lower():
                return(self.jsonResponse[i]['codename'])

#################################
## This private method returns ##
## the organization ID         ##
#################################
    def __getOrgID(self, codename):
        for i in range (len(self.jsonResponse)):
            if self.jsonResponse[i]['codename'].lower() == codename.lower():
                return(self.jsonResponse[i]['organization_id'])

######################################
## This returns the target category ##
######################################
    def getCategory(self, codename):
        for i in range (len(self.jsonResponse)):
            if self.jsonResponse[i]['codename'].lower() == codename.lower():
                return(self.jsonResponse[i]['category']['name'])

#####################################################
## This will connect you to the target by codename ##
#####################################################
    def connectToTarget(self, codename):
        slug = self.getTargetID(codename)
        response = self.try_requests("PUT", URL_ACTIVATE_TARGET, 10, slug)
        time.sleep(5)
        return response.status_code

########################################################
## This just returns the "real" client name sometimes ##
########################################################
    def clientName(self, codename):
        for i in range (len(self.jsonResponse)):
            if self.jsonResponse[i]['codename'].lower() == codename.lower():
                return(self.jsonResponse[i]['name'])


################################
## This gets the target scope ##
################################

    def getScope(self, codename):
        category = self.getCategory(codename)
        orgID = self.__getOrgID(codename)
        slug = self.getTargetID(codename)
        if category.lower() == "web application":
            scopeURL = "https://platform.synack.com/api/asset/v1/organizations/"+orgID+"/owners/listings/"+slug+"/webapps"
            allRules = []
            oosRules = []
            response = self.try_requests("GET", scopeURL, 10)
            jsonResponse = response.json()
            j = 0
            while j < len(jsonResponse):
                if jsonResponse[j]['status'] in ["out","tbd"]:
                    tmpOOS = set()
                    for thisRule in range(len(jsonResponse[j]['rules'])):
                        url = urlparse(jsonResponse[j]['rules'][thisRule]['rule'])
                        scheme = url.scheme
                        netloc = url.netloc
                        path   = url.path
                        port   = url.port
                        wildcard = False
                        if len(netloc) != 0:
                            subdomain = netloc.split('.')[0]
                            if subdomain == "*":
                                wildcard = True
                                netloc = ".".join(netloc.split('.')[1:])
                        else:
                            if len(path) != 0:
                                netloc = path.split('/')[0]
                                checkWildcard = netloc.split('.')[0]
                                if checkWildcard == "*":
                                    wildcard = True
                                    if ":" in netloc:
                                        port = netloc.split(':')[1]
                                        thisURL = netloc.split(':')[0]
                                        netloc = ".".join(thisURL.split('.')[1:])
                                    else:
                                        port = 443
                                        netloc = ".".join(netloc.split('.')[1:])
                                else:
                                    if ":" in netloc:
                                        port = netloc.split(':')[1]
                                        thisURL = netloc.split(':')[0]
                                        netloc = ".".join(thisURL.split('.')[0:])
                                    else:
                                        port = 443
                                        netloc = ".".join(netloc.split('.')[0:])
                                path = "/" + "/".join(path.split('/')[1:])
                            else:
                                continue
                        oosDict = {
                                        'scheme' : scheme,
                                        'netloc': netloc,
                                        'path': path,
                                        'port': port,
                                        'wildcard': wildcard,
                                        'fullURI' : scheme+netloc

                        }
                    oosRules.append(oosDict)
                    j+=1
                else:
                    for thisRule in range(len(jsonResponse[j]['rules'])):
                        url = urlparse(jsonResponse[j]['rules'][thisRule]['rule'])
                        scheme = url.scheme
                        netloc = url.netloc
                        path   = url.path
                        port   = url.port
                        wildcard = False

                        if len(netloc) != 0:
                            subdomain = netloc.split('.')[0]
                            if subdomain == "*":
                                wildcard = True
                                netloc = ".".join(netloc.split('.')[1:])
                        else:
                            if len(path) != 0:
                                netloc = path.split('/')[0]
                                checkWildcard = netloc.split('.')[0]
                                if checkWildcard == "*":
                                    wildcard = True
                                    if ":" in netloc:
                                        port = netloc.split(':')[1]
                                        thisURL = netloc.split(':')[0]
                                        netloc = ".".join(thisURL.split('.')[1:])
                                    else:
                                        port = 443
                                        netloc = ".".join(netloc.split('.')[1:])
                                else:
                                    if ":" in netloc:
                                        port = netloc.split(':')[1]
                                        thisURL = netloc.split(':')[0]
                                        netloc = ".".join(thisURL.split('.')[0:])
                                    else:
                                        port = 443
                                        netloc = ".".join(netloc.split('.')[0:])
                                path = "/" + "/".join(path.split('/')[1:])
                            else:
                                continue
                        if jsonResponse[j]['rules'][thisRule]['status'] in ["out","tbd"]:
                            oosDict = {
                                        'scheme' : scheme,
                                        'netloc': netloc,
                                        'path': path,
                                        'port': port,
                                        'wildcard': wildcard,
                                        'fullURI' : scheme+netloc

                            }
                            oosRules.append(oosDict)
                            continue
                        else:
                            pass

                        scopeDict = {
                                        'scheme' : scheme,
                                        'netloc': netloc,
                                        'path': path,
                                        'port': port,
                                        'wildcard': wildcard,
                                        'fullURI' : scheme+netloc
                                    }
                    allRules.append(scopeDict)
                    j+=1
            return(list(allRules),list(oosRules))
        if category.lower() == "host":
            scopeURL = "https://platform.synack.com/api/targets/"+slug+"/cidrs?page=all"
            cidrs = []
            try:
                response = self.try_requests("GET", scopeURL, 10)
            except requests.exceptions.RequestException as e:
                raise SystemExit(e)
            temp = json.dumps(response.json()['cidrs']).replace("[","").replace("]","").replace("\"","").replace(", ","\n").split("\n")
            cidrs.extend(temp)
            cidrs = list(set(cidrs))
            return(cidrs)

########################################
## This converts CIDR list to IP list ##
## This is a much faster method, previous method was causing problems on large hosts ##
########################################
    def getIPs(self, cidrs):
        IPs = []
        for i in range(len(cidrs)):
            if cidrs[i] != "":
                for ip in IPNetwork(cidrs[i]):
                    IPs.append(str(ip))
        return(IPs)

##############################################
## This gets all of your passed assessments ##
##############################################
    def getAssessments(self):
        self.assessments.clear()
        response = self.try_requests("GET", URL_ASSESMENTS, 10)
        jsonResponse = response.json()
        for i in range(len(jsonResponse)):
            if jsonResponse[i]['written_assessment']['passed'] == True:
                self.assessments.append(jsonResponse[i]['category_name'])
            i+=1

##########################################################
## This gets endpoints from Web Application "Analytics" ##
##########################################################
    def getAnalytics(self, codename):
        slug = self.getTargetID(codename)

        output = {}

        # Submissions and Submissions 48h
        resp_sub_alltime = self.try_requests("GET", URL_ANALYTICS_SUBMISSION + slug, 10)
        if resp_sub_alltime.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_all_time'] = resp_sub_alltime.json()['value']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")

        resp_sub_48h = self.try_requests("GET", URL_ANALYTICS_SUBMISSION + slug + "&period=48h",10)
        if resp_sub_48h.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_48h'] = resp_sub_48h.json()['value']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")

        # Connections
        resp_connections = self.try_requests("GET", URL_ANALYTICS_CONNECTIONS + slug,10)
        if resp_connections.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_connections_current'] = resp_connections.json()['value']['current_connections']
            output['submissions_connections_all_time'] = resp_connections.json()['value']['lifetime_connections']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")


        # Accepted, Rejected and Queue
        resp_accepted = self.try_requests("GET", URL_ANALYTICS_CATEGROIES + slug + "&status=accepted",10)
        if resp_accepted.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_accepted'] = resp_accepted.json()['value']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")


        resp_rejected = self.try_requests("GET", URL_ANALYTICS_CATEGROIES + slug + "&status=rejected",10)
        if resp_rejected.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_rejected'] = resp_rejected.json()['value']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")


        resp_queue = self.try_requests("GET", URL_ANALYTICS_CATEGROIES + slug + "&status=in_queue",10)
        if resp_queue.status_code != 200:
            log.error(f"Error fetching analytics for '{codename}'")
            return
        try:
            output['submissions_queue'] = resp_queue.json()['value']
        except BaseException as e:
            log.error(f"Error fetching analytics for '{codename}': {e}")

        return output

#############################################
## This registers all unregistered targets ##
#############################################

    def registerAll(self):
        lpplus = False
        newly_registered = []
        pageNum = 1
        next_page = True
        unregistered_slugs = []
        while next_page:
            url_slugs = URL_UNREGISTERED_SLUGS + str(pageNum)
            response = self.try_requests("GET", url_slugs, 10)
            if response.status_code != 200:
                return []
            jsonResponse = response.json()
            if (len(jsonResponse)!=0):
                for i in range (len(jsonResponse)):
                    if jsonResponse[i]["category"]["name"] in self.assessments and jsonResponse[i]["slug"] not in self.ignore_slugs:
                        log.debug(f"Adding to unregistered_slugs: {jsonResponse[i]['slug']}")
                        unregistered_slugs.append(str(jsonResponse[i]["slug"]))
                pageNum += 1
            else:
                next_page = False
                pageNum += 1
        for i in range (len(unregistered_slugs)):
            url_register_slug = "https://platform.synack.com/api/targets/"+unregistered_slugs[i]+"/signup"
            data='{"ResearcherListing":{"terms":1}}'
            log.debug(f"Processing {url_register_slug}")
            response = self.try_requests("POST", url_register_slug, 10, data)
            log.debug(f"Response status is {response.status_code}")
            # slug = unregistered_slugs[i]

        self.getAllTargets()
        for i in range(len(unregistered_slugs)):
            log.debug(f"Processing slug {unregistered_slugs[i]}")
            codename = self.getCodenameFromSlug(unregistered_slugs[i])
            log.debug(f"Processing codename {codename}")
            if codename == None:
                log.error("Error registering "+unregistered_slugs[i]+"!")
                self.ignore_slugs.append(unregistered_slugs[i])
                lpplus = True
            else:
                log.info("Successfully registered "+str(codename))
                # newly_registered.append(unregistered_slugs[i])
                # print(f"Added {unregistered_slugs[i]} to newly_registered")

        if len(unregistered_slugs) > 0:
            log.debug("Now saving 'jsonResponse', 'self.jsonResponse', 'unregistered_slugs''' to a file to see what data we actually need to add to newly_registered")
            with open("jsonResponse.json", mode='wt', encoding='utf-8') as out:
                json.dump(jsonResponse, out)
            out.close()

            with open("self.jsonResponse.json", mode='wt', encoding='utf-8') as out:
                json.dump(self.jsonResponse, out)
            out.close()

            with open("unregistered_slugs.json", mode='wt', encoding='utf-8') as out:
                json.dump(unregistered_slugs, out)
            out.close()
            log.debug("Now processing return values")
            for i in range(len(unregistered_slugs)):
                for j in range(len(jsonResponse)):
                    log.debug(f"unregistered slug is {unregistered_slugs[i]}")
                    log.debug(f"self.jsonResponse[j]['slug'] is {jsonResponse[j]['slug']}")
                    if jsonResponse[j]["slug"].lower() == unregistered_slugs[i].lower():
                        log.debug("Adding to newly registered")
                        newly_registered.append(jsonResponse[j])

        if lpplus:
            log.warning("There is propably a lp+ target which did not register - review manually")
            return -1

        if len(newly_registered) > 0:
            log.debug(f"Going to return newly_registered to bot which content is: {newly_registered}")
        return newly_registered

###############
## Keepalive ##
###############
    def connectToPlatform(self):
        # Pull a valid CSRF token for requests in login flow
        response = self.try_requests("GET", "https://login.synack.com/", 10)
        # <meta name="csrf-token" content="..."/>
        m = re.search('<meta name="csrf-token" content="([^"]*)"', response.text)
        csrf_token = m.group(1)
        self.webheaders['X-CSRF-Token'] = csrf_token

        # fix broken Incapsula cookies - regression removed
        for cookie_name in self.session.cookies.iterkeys():
            cookie_value = self.session.cookies.get(cookie_name)
            if cookie_value.find("\r") > -1 or cookie_value.find("\n") > -1:
                log.debug("Fixing cookie %s" % cookie_name)
                cookie_value = re.sub("\r\n *","", cookie_value)
                cookie_obj = requests.cookies.create_cookie(name=cookie_name,value=cookie_value,path="/")
                self.session.cookies.clear(domain="login.synack.com",path="/",name=cookie_name)
                self.session.cookies.set_cookie(cookie_obj)

        data={"email":self.email,"password":self.password}
        log.info("Logging in with username and password")
        response = self.try_requests("POST", "https://login.synack.com/api/authenticate", 1, data)
        jsonResponse = response.json()
        if not jsonResponse['success']:
            log.error("Error logging in: "+jsonResponse)
            return False
        log.info("Login was successfull")

        progress_token = jsonResponse['progress_token']

        log.info("Logging in with 2FA")
        data={"authy_token":self.getAuthy(),"progress_token":progress_token}
        response = self.try_requests("POST", "https://login.synack.com/api/authenticate", 1, data)
        jsonResponse = response.json()

        grant_token = jsonResponse['grant_token']

        # 2 requests required here to confirm the grant token - once to the HTML page and once to the API
        response = self.try_requests("GET", "https://platform.synack.com/?grant_token="+grant_token, 1)
        self.webheaders['X-Requested-With'] = "XMLHttpRequest"
        response = self.try_requests("GET", "https://platform.synack.com/token?grant_token="+grant_token, 1)
        jsonResponse = response.json()
        access_token = jsonResponse['access_token']

        self.token = access_token
        with open(self.sessionTokenPath,"w") as f:
            f.write(self.token)
        f.close()

        # Remove these headers so they don't affect other requests
        del self.webheaders['X-Requested-With']
        del self.webheaders['X-CSRF-Token']
        log.info("Connected to the platform")


###########
## Vulns ##
###########

    def getVulns(self, status="accepted"):
        pageNum = 1
        results = []
        while True:
            url_vuln = URL_VULNERABILITIES +"?filters%5Bstatus%5D=" + status + "&page=" +str(pageNum)+"&per_page=5"
            response = self.try_requests("GET", url_vuln, 10)
            vulnsResponse = response.json()
            if len(vulnsResponse) == 0:
                break
            else:
                results = results + vulnsResponse
                pageNum += 1
        return results

    def getVuln(self, identifier): # e.g. optimusant-4
        url_vuln = URL_VULNERABILITIES + "/" + identifier
        response = self.try_requests("GET", url_vuln, 10)
        vuln_response = response.json()
        return vuln_response

###########
## Drafts ##
###########

    def getDrafts(self):
        pageNum = 1
        results = []
        while True:
            url_drafts = URL_DRAFTS +"?page=" +str(pageNum)+"&per_page=5"
            response = self.try_requests("GET", url_drafts, 10)
            draftsResponse = response.json()
            if len(draftsResponse) == 0:
                break
            else:
                results = results + draftsResponse
                pageNum += 1
        return results

    def deleteDraft(self, id):
        # careful!!
        url_delete = URL_DRAFTS + "/" + str(id)
        response = self.try_requests("DELETE", url_delete, 1)
        if response.status_code == 200:
            return True
        else:
            return False

###########
## Hydra ##
###########

    def getHydra(self, codename):
        slug = self.getTargetID(codename)
        pageNum = 1
        hydraResults = []
        while True:
            url_hydra = URL_HYDRA +"?page=" +str(pageNum)+"&listing_uids="+slug+"&q=%2Bport_is_open%3Atrue"
            response = self.try_requests("GET", url_hydra, 10)
            hydraResponse = response.json()
            if len(hydraResponse) == 0:
                break
            else:
                hydraResults = hydraResults + hydraResponse
                pageNum += 1
        return hydraResults

###################
## Mission stuff ##
###################

## Get possible claim amount

    def getClaimThreshold(self):
        response = self.try_requests("GET", URL_PROFILE,10)
        if response.status_code == 200:
            try:
                info = response.json()
            except BaseException as e:
                log.error(f"There was an error getting the claim limit: {e}")
                return 0
        else:
            log.error(f"There was an error getting the claim limit - code {response.status_code}")
            return 0

        max_limit = info['claim_limit']

        response = self.try_requests("GET", URL_CLAIMED_AMOUNT, 10)
        if response.status_code == 200:
            try:
                claimed = response.json()
            except BaseException as e:
                log.error(f"There was an error getting the already claimed amount: {e}")
                return 0
        else:
            log.error(f"There was an error getting the already claimed amount - code {response.status_code}")
            return 0

        already_claimed = claimed['claimedAmount']

        available_claimable_amount = max_limit - already_claimed

        return available_claimable_amount


## Poll for missions ##

    def pollMissions(self):
        response = self.try_requests("GET", URL_PUBLISHED_MISSIONS, 10)
        try:
            jsonResponse = response.json()
        except:
            jsonResponse = {}
        try:
            return jsonResponse
        except NameError:
            jsonResponse = {}
        return jsonResponse

####################
## CLAIM MISSIONS ##
####################
    def claimMission(self, missionJson):
        dollarValue = {}
        claim = {'type': 'CLAIM'}
        # limit = self.getClaimThreshold()
################
## Sort missions by dollar amount high to low
################
        for i in range(len(missionJson)):
            dollarValue[i] = missionJson[i]["payout"]["amount"]
        sorted_tuples = sorted(dollarValue.items(), key=operator.itemgetter(1), reverse=True)
        sorted_dict = {k: v for k, v in sorted_tuples}
################
        i = len(sorted_dict.keys())
        claimable_dict = {}
        # for key in sorted_dict:
        #     if missionJson[key]['payout']['amount'] <= limit:
        #         log.info(f"Adding {missionJson[key]['title']} for {missionJson[key]['payout']['amount']} $ to claimable list")
        #         claimable_dict[key] = sorted_dict[key]
        missionList = []
        for key in claimable_dict.keys():
            claimable_mission = missionJson[key]
            i-= 1
            campaignID = missionJson[key]["campaign"]["id"]
            orgID = missionJson[key]["organization"]["id"]
            slug = missionJson[key]["listing"]["id"]
            taskID = missionJson[key]["id"]
            url_claimPath = "https://platform.synack.com/api/tasks/v1/organizations/" + orgID + "/listings/" + slug + "/campaigns/" + campaignID + "/tasks/" + taskID + "/transitions"
            claimResponse = self.try_requests("POST", url_claimPath, 10, claim)
            if claimResponse.status_code == 201:
                claimed = True
            else:
                log.warning(f"Claiming failed - status code {claimResponse.status_code}")
                claimed = False

            missionDict = {
                "title": claimable_mission['title'],
                "categories": ', '.join(claimable_mission['categories']),
                "asset_types": ', '.join(claimable_mission['assetType']),
                "organization": claimable_mission['organization']['title'],
                "listing": claimable_mission['listing']['title'],
                "payout": claimable_mission['payout']['amount'],
                "finishing_time": str(datetime.timedelta(seconds=claimable_mission['durationInSecs'])),
                "claimed": claimed
            }

            missionList.append(missionDict)
        return(missionList)

########################
## Notification Token ##
########################

    def getNotificationToken(self):
        response = self.try_requests("GET", URL_NOTIFICATION_TOKEN, 10)
        try:
            jsonResponse = response.json()
        except:
            jsonResponse = {}
            return(1)
        self.notificationToken = jsonResponse['token']
        with open(self.notificationTokenPath,"w") as f:
            f.write(self.notificationToken)
        return(0)

############################
## Read All Notifications ##
############################

    def markNotificationsRead(self):
        if not self.notificationToken:
            self.getNotificationToken()
        readNotifications = URL_NOTIFICATION_API+"read_all?authorization_token="+self.notificationToken
        del self.webheaders['Authorization']
        response = self.try_requests("POST", readNotifications, 10)
        self.webheaders['Authorization'] = "Bearer " + self.token
        try:
            textResponse = str(response.content)
        except:
            return(1)
        return(0)

########################
## Read Notifications ##
########################

    def checkUnreadNotificationsCount(self):
        if not self.notificationToken:
            self.getNotificationToken()

        unreadCountUrl = URL_NOTIFICATION_API+"notifications/unread_count?authorization_token="+self.notificationToken
        self.webheaders['Authorization'] = "Bearer " + self.notificationToken
        response = self.try_requests("GET",unreadCountUrl,10)
        self.webheaders['Authorization'] = "Bearer " + self.token
        if response.status_code == 422:
                log.debug("Need to refresh the notification token")
                self.getNotificationToken()
                return 0
        if response.status_code != 200:
            return 0
        try:
            jsonResponse = response.json()
        except:
            return 0

        return jsonResponse['unread_count']

    def pollNotifications(self):
        pageIterator=1
        breakOuterLoop = 0
        notifications = []
        if not self.notificationToken:
            self.getNotificationToken()
        while True:
            notificationsUrl = URL_NOTIFICATION_API+"notifications?pagination%5Bpage%5D="+str(pageIterator)+"&pagination%5Bper_page%5D=15&meta=1"
            self.webheaders['Authorization'] = "Bearer " + self.notificationToken
            response = self.try_requests("GET", notificationsUrl, 10)
            self.webheaders['Authorization'] = "Bearer " + self.token
            try:
                jsonResponse = response.json()
            except:
                return []
            if not jsonResponse:
                break
            if response.status_code == 422:
                log.debug("Need to refresh the notification token")
                self.getNotificationToken()
                return []
            for i in range(len(jsonResponse)):
                if jsonResponse[i]["read"] == False:
                    notifications.append(jsonResponse[i])
                else:
                    breakOuterLoop=1
                    break
            if breakOuterLoop == 1:
                break
            else:
                pageIterator=pageIterator+1
        return(notifications)


###################
## Read Messages ##
###################

    def checkUnreadMessageCount(self):
        response = self.try_requests("GET",URL_UNREAD_MESSAGE_COUNT,10)
        if response.status_code != 200:
            return 0
        try:
            jsonResponse = response.json()
        except:
            return 0

        return jsonResponse['unread_count']

    def pollMessages(self):
        pageIterator=1
        breakOuterLoop = 0
        messages = []

        while True:
            messagesUrl = f"https://platform.synack.com/api/conversations?pagination%5Bpage%5D={str(pageIterator)}&pagination%5Bper_page%5D=15"
            self.webheaders['Authorization'] = f"Bearer {self.token}"
            response = self.try_requests("GET",messagesUrl,10)
            if response.status_code != 200:
                return []
            try:
                jsonResponse = response.json()
            except:
                return []
            if not jsonResponse:
                break
            for i in range(len(jsonResponse)):
                if jsonResponse[i]["read"] == False:
                    messages.append(jsonResponse[i])
                else:
                    breakOuterLoop = 1
                    break

            if breakOuterLoop == 1:
                break
            else:
                pageIterator+=1

        return(messages)


#############################
## Get Current Target Slug ##
#############################

    def getCurrentTargetSlug(self):
        response = self.try_requests("GET", URL_ACTIVATE_TARGET, 10)
        try:
            jsonResponse = response.json()
        except:
            return(1)
        if jsonResponse['slug']:
            return(jsonResponse['slug'])

##############
## Get ROEs ##
##############

    def getRoes(self, slug):
        requestURL = URL_SCOPE_SUMMARY + str(slug)
        response = self.try_requests("GET", requestURL, 10)
        roes = list()
        try:
            jsonResponse = response.json()
        except:
            return(1)
        if not jsonResponse['roes']:
            return(roes)
        else:
            for i in range(len(jsonResponse['roes'])):
                roes.append(jsonResponse['roes'][i])
            return(roes)

######################
## Get Transactions ##
######################
    def getTransactions(self):
        pageIterator=1
        transactions = []
        while True:
            transactionUrl = URL_TRANSACTIONS+"?page="+str(pageIterator)+"&per_page=15"
            response = self.try_requests("GET", transactionUrl, 10)
            try:
                jsonResponse = response.json()
                for i in range(len(jsonResponse)):
                    transactions.append(jsonResponse[i])
            except:
                return
            if not jsonResponse:
                break

            pageIterator=pageIterator+1


        overall_sum = 0
        mission_sum = 0
        patch_sum = 0
        vuln_sum = 0
        cash_out_sum = 0 # This will be negative

        for i in range(len(transactions)):
            f_amount = float(transactions[i]['amount'])
            reference_type = transactions[i]['reference_type']
            if transactions[i]['title'] == "CashOut" or reference_type == 'CashOut':
                cash_out_sum += f_amount
            else:
                overall_sum += f_amount
                if reference_type == "Task":
                    mission_sum += f_amount
                elif reference_type == "PatchVerification":
                    patch_sum += f_amount
                elif reference_type == "Vulnerability":
                    vuln_sum += f_amount

        balance = overall_sum - cash_out_sum

        table_headers = ["Reference Type", "Amount"]
        data = [
            ["Missions", f"$ {mission_sum}"],
            ["Patch Verifications", f"$ {patch_sum}"],
            ["Vulnerabilities", f"$ {vuln_sum}"],
            ["",""],
            ["Total Earned", f"$ {overall_sum}"],
            ["Cashed Out", f"$ {cash_out_sum}"],
            ["",""],
            ["Balance", f"$ {balance}"],
        ]

        print("")
        print(tabulate(data, headers=table_headers))
