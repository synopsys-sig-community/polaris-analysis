import argparse
import json
import logging
import os
import re
import sys
from urllib.parse import urlparse
import requests
from timeit import default_timer as timer
from datetime import datetime, timedelta
from os.path import exists
import polling
import hashlib

__author__ = "Jouni Lehto"
__versionro__="0.1.10"

MAX_LIMIT=1000
SCAN_TIMEOUT=1800 #Polaris scan/analysis timeout in seconds 1800s = 30min

class PolarisResultsToSarif:

    def __init__(self, url, token, email=None, password=None):
        self.url = url
        self.token = token
        self.email = email
        self.password = password
        self.jwt = self.__getJwt(url, token, email, password)

    def __getJwt(self, baseUrl, token, email, password):
        endpoint = f'{baseUrl}/api/auth/v2/authenticate'
        headers = { 'Accept' : 'application/json', 'Content-Type' : 'application/x-www-form-urlencoded' }
        if token != None:
            params = { 'accesstoken' : token }
        else:
            params = { 'email' : email, 'password' : password }
        response = requests.post(endpoint, headers=headers, data=params)
        if response.status_code != 200: logging.ERROR(response.json()['errors'][0])
        return response.json()['jwt']

    def __getHeaders(self):
        headers = { 'Authorization' : 'Bearer ' + self.jwt, 'Content-Type' : 'application/vnd.api+json' }
        return headers
    
    def __getIssues(self, projectId, branchId, runId, limit=MAX_LIMIT, filter=None, events=False):
        dictionary = []
        issues_data = []
        issues_included = []

        endpoint = self.url + '/api/query/v1/issues'
        params = None
        if args.status:
            params = dict([
                ('project-id', projectId),
                ('filter[issue][status][eq]', args.status),
                ('include[issue][]', ['severity', 'related-indicators', 'related-taxa'])
                ])
        else:
            params = dict([
                ('project-id', projectId),
                ('include[issue][]', ['severity', 'related-indicators', 'related-taxa'])
                ])

        # filter by runId or branchId but not both
        if runId is not None: params['run-id[]'] = runId
        else: params['branch-id'] = branchId

        # update params with optional user-specified filter
        if filter:
            params.update(filter)

        issues_data, issues_included = self.__getPaginatedData(endpoint, params, limit)
        if issues_data == []:
            return []

        # Create the base url so we can build an issue url later
        # branchId is not guaranteed to be known here, so that is added later during issue processing
        __baseUrl = issues_data[0]['links']['self']['href']
        data = urlparse(__baseUrl)
        __baseUrl = data.scheme + '://' + data.netloc
        __baseUrl += '/projects/' + projectId

        # loop over the list of issues
        for issue in issues_data:
            issueKey = issue['attributes']['issue-key']
            findingKey = issue['attributes']['finding-key']
            checker = issue['attributes']['sub-tool']
            issue_type_id = issue['relationships']['issue-type']['data']['id']
            issue_path_id = issue['relationships']['path']['data']['id']
            try: severity = issue['relationships']['severity']['data']['id']
            except: severity = None

            # [0] = first detected
            # [1] = fixed by code change
            issue_opened_id = issue['relationships']['transitions']['data'][0]['id']

            cwe = None
            try:
                # There can be several CWEs, so merge them all in to a single string
                for taxa_data in issue['relationships']['related-taxa']['data']:
                    if cwe is None:
                        cwe = taxa_data['id']
                    else:
                        cwe += "," + taxa_data['id']
            except: cwe = None

            indicators = None
            if issue['relationships']['related-indicators']['data']:
                indicator_list = []
                for ind_dct in issue['relationships']['related-indicators']['data']:
                    for ind_key, val in ind_dct.items():
                        if ind_key == 'id':
                            indicator_list.append(val)
                indicators = ','.join(indicator_list)

            # iterate through included to get name, description, local-effect, issue-type
            for issue_included in issues_included:
                if issue_included['id'] == issue_type_id:
                    try: name = issue_included['attributes']['name']
                    except: name = None
                    try: description = issue_included['attributes']['description']
                    except: description = None
                    try: local_effect = issue_included['attributes']['local-effect']
                    except: local_effect = None
                    try: type = issue_included['attributes']['issue-type']
                    except: type = None

                if issue_included['id'] == issue_path_id:
                    dirsep = '/'
                    try: path = dirsep.join(issue_included['attributes']['path'])
                    except: path = None

                if issue_included['id'] == issue_opened_id:
                    state = issue_included['attributes']['transition-type']
                    cause = issue_included['attributes']['cause']
                    causeDesc = issue_included['attributes']['human-readable-cause']
                    branchId = issue_included['attributes']['branch-id']
                    revisionId = issue_included['attributes']['revision-id']

                    # Construct issue URL
                    url = __baseUrl + '/branches/' + branchId
                    url += '/revisions/'
                    url += revisionId
                    url += '/issues/' + issueKey

            if events:
                if runId == None:
                    print("FATAL: runId required by events endpoint, caller should set")
                    sys.exit(1)
                endpoint = self.url + '/api/code-analysis/v0/events-with-source'
                params = dict([('finding-key', str(findingKey)),
                    ('run-id', runId),
                    ('locator-path', str(path))
                    ])
                headers = self.__getHeaders()
                headers['Accept-Language'] = 'en'

                try:
                    response = requests.get(endpoint, params=params, headers=headers)
                    if response.status_code != 200: logging.error(response.json()['errors'][0])
                except Exception as e:
                    logging.exception(e)

                line = response.json()['data'][0]['main-event-line-number']

                # Save main event (mainevent_description, mainevent_source, support_description)
                subEvents, remediation = self.__getMainEvent(response.json()['data'][0]['events'])

            # create the dictionary entry
            entry = {'projectId': projectId, 'branchId': branchId, \
                'issue-key': issueKey, 'finding-key': findingKey, \
                'checker': checker, 'severity': severity, \
                'type': type, 'local_effect': local_effect, 'name': name, \
                'description': description, 'path': path, \
                'url': url, \
                'state' : state, 'cause' : cause, 'causeDesc' : causeDesc,
                'cwe' : cwe, 'indicators' : indicators, \
                'branchId' : branchId, 'revisionId' : revisionId,'line-number': line, \
                'remediation' : remediation
                }
            if events:
                entry['subevents'] = subEvents

            dictionary.append(entry)

        return dictionary

    def __getPaginatedData(self, endpoint, params={}, limit=MAX_LIMIT):
        offset = 0
        total = limit + 1
        data = []
        included = []

        params['page[limit]'] = str(limit)
        params['page[offset]'] = str(offset)

        while (offset < total):
            if (logging.getLogger().isEnabledFor(logging.DEBUG)): logging.debug(f'endpoint: {endpoint} , GET, params: {params}')
            response = requests.get(endpoint, params=params, headers=self.__getHeaders())
            if response.status_code != 200: logging.error(response.json()['errors'][0])
            if (response.json()['data'] == []):
                # Return empty list (or 2 empty lists for issues endpoint)
                p = re.compile(r'api\/query\/v\d+\/issues')
                if p.search(endpoint):
                    return [], []
                else:
                    return []

            # we actually only need to fetch total once
            total = response.json()['meta']['total']

            if (data == []):
                # A single data element can have confusing results with extend, so make
                # sure we initialize cleanly
                data = response.json()['data']
            else:
                data.extend(response.json()['data'])

            try: included.extend(response.json()['included'])
            except: pass

            # update the offset to the next page
            offset += limit
            params['page[offset]'] = str(offset)

            # if limit is less than MAX_LIMIT, assume we are after the first N records
            if (limit < MAX_LIMIT): break

        if (included == []): return data
        else: return data, included

    def __getMainEvent(self, eventList):
        subEvents = []
        remediation = ""
        for event in sorted(eventList, key=lambda x: x['event-number']):
            subEvent = {}
            subEvent['event-number'] = event['event-number']
            if event['event-type'] == "MAIN":
                subEvent['mainevent_description'] = event['event-description']
            else:
                # This will often contain remediation guidance, but it can also have more general
                # support information. There's no simple way to distinguish the two.
                subEvent['support_description'] = event['event-description']
            if 'source-before' in event and event['source-before']:
                subEvent['start-line'] = event['source-before']['start-line']
                subEvent['end-line'] = event['source-before']['end-line']
                subEvent['source-code'] = event['source-before']['source-code']
            elif event['source-after']:
                subEvent['start-line'] = event['source-after']['start-line']
                subEvent['end-line'] = event['source-after']['end-line']
                subEvent['source-code'] = event['source-after']['source-code']
            if event['event-tag'] == 'remediation':
                remediation = event['event-description']
            subEvents.append(subEvent)
        return subEvents, remediation


    # Get the projectID with the project name and
    # branchId with the given branchName and projectId
    # PARAMS: 
    #   projectName = The Project name in Polaris
    #   branchName = The Branch name in Polaris
    def getProjectandBranchIds(self, projectName, branchName):
        endpoint = f"{self.url}/api/common/v0/projects"
        params = dict([
            ('page[limit]', 10),
            ('filter[project][name][eq]', projectName)
        ])
        response = requests.get(endpoint, params=params, headers=self.__getHeaders())
        if response.status_code != 200: logging.error(response.json()['errors'][0])

        if response.json()['meta']['total'] == 0:
            logging.error(f'FATAL: project {projectName} not found')
            sys.exit(1)
        projectId = response.json()['data'][0]['id']
        # Get the project banchid with projectid and given branchName
        endpoint = f"{self.url}/api/common/v0/branches"
        params = dict([
            ('page[limit]', 10),
            ('filter[branch][project][id][eq]', projectId),
            ('filter[branch][name][eq]', branchName)
        ])
        response = requests.get(endpoint, params=params, headers=self.__getHeaders())
        if response.status_code != 200: logging.error(response.json()['errors'][0])
        if response.json()['meta']['total'] == 0:
            logging.error(f'FATAL: branch {branchName} not found')
            sys.exit(1)
        branchId = response.json()['data'][0]['id']
        return projectId, branchId

    def getJobs(self, projectId, branchId):
        MAX_LIMIT_JOBS=500 #Max limit 500 is a max limit in API endoint.
        endpoint = self.url + '/api/jobs/v2/jobs'
        params = dict([
            ('page[limit]', MAX_LIMIT_JOBS),
            ('filter[jobs][project][id]', projectId),
            ('filter[jobs][branch][id]', branchId)
            ])
        response = requests.get(endpoint, params=params, headers=self.__getHeaders())
        logging.debug(f"Total amount of jobs done: {response.json()['meta']['total']}")
        if response.status_code != 200: logging.error(response.json()['errors'][0])
        jobs = response.json() 
        if jobs['data'] and len(jobs['data']) > 0:
            #Check that do we have all scanning jobs or not
            all_data = jobs['data']
            if "total" in jobs['meta']:
                total = jobs['meta']['total']
                downloaded = MAX_LIMIT_JOBS
                while total > downloaded:
                    logging.debug(f"getting next page {downloaded}/{total}")
                    params = dict([
                        ('page[limit]', MAX_LIMIT_JOBS),
                        ('page[offset]', downloaded),
                        ('filter[jobs][project][id]', projectId),
                        ('filter[jobs][branch][id]', branchId)
                        ])
                    response = requests.get(endpoint, params=params, headers=self.__getHeaders())
                    if response.status_code != 200: logging.error(response.json()['errors'][0])
                    all_data.extend(response.json()['data'])
                    downloaded += MAX_LIMIT_JOBS
            # loop over the list of jobs and sort the newest first
            jobs['data'].sort(key=lambda x: datetime.strptime(x['attributes']['dateCreated'], '%Y-%m-%dT%H:%M:%S.%fZ'), reverse=True)
            state = jobs['data'][0]['status']['state']
            jobId = jobs['data'][0]['id']
            logging.debug(f"The newest job was created: {jobs['data'][0]['attributes']['dateCreated']}")
            if not state == 'COMPLETED':
                polling.poll(lambda: self.__checkStatus(jobId), check_success=self.__checkSuccess, step=4, timeout=SCAN_TIMEOUT)
                return self.getJobInfo(jobId)
            else:
                return {
                    'projectId': jobs['data'][0]['attributes']['projectId'].split(':')[3],
                    'branchId': jobs['data'][0]['attributes']['branchId'].split(':')[3],
                    'runId': jobs['data'][0]['attributes']['runId'].split(':')[3]
                }
        else:
            logging.error("No scanning jobs found!")

    def __checkStatus(self,job_id):
        response = requests.get(f'{self.url}/api/jobs/v2/jobs/{job_id}', headers=self.__getHeaders())
        return response

    def __checkSuccess(self, response):
        if response.status_code == 200:
            if response.json()['status']['state'].lower() == "completed":
                return True
            elif response.json()['status']['state'].lower() == "failed":
                logging.error("Scan has failed!")
                return True
            elif response.json()['status']['state'].lower() == "cancelled":
                logging.error("Scan has been canceled!")
                return True
            else:
                logging.info("Scan is not ready yet, status: " + response.json()['status']['state'])
        return False

    def getJobInfo(self, jobId):
        params = {}
        entry = {}
        endpoint = f"{self.url}/api/jobs/v2/jobs/{jobId}"
        params['page[limit]'] = str(MAX_LIMIT)
        params['page[offset]'] = str(0)
        response = requests.get(endpoint, params=params, headers=self.__getHeaders())
        if response.status_code == 200:
            job = response.json()
            entry = {
                'projectId': job['attributes']['projectId'].split(':')[3],
                'branchId': job['attributes']['branchId'].split(':')[3],
                'runId': job['attributes']['runId'].split(':')[3],
            }
        return entry

    def getSarifJsonHeader(self):
        return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

    def getResults(self, jobInfo):
        issues_data = self.__getIssues(projectId=jobInfo['projectId'], branchId=jobInfo['branchId'], runId=jobInfo['runId'], events=True)
        ruleIds, rules, issues = [],[],[]
        sarifIssues = {}
        if issues_data and len(issues_data) > 0:
            logging.debug(f'Got {len(issues_data)} issues')
            for issue in issues_data:
                locations = []
                #Create a new rule if its not created yet
                rulesId = f"{issue['checker']}/{issue['type']}"
                ruleFullDescription = ""
                if "description" in issue: ruleFullDescription += f'Description: {issue["description"]}\n'
                if not rulesId in ruleIds:
                    rule = {"id": rulesId, "name": issue["checker"], "helpUri": issue["url"], "shortDescription": {"text": issue["name"]}, 
                            "fullDescription": {"text": f'{ruleFullDescription[:1000] if not ruleFullDescription == "" else "N/A"}'},
                            "help":{"text":f'{ruleFullDescription[:1000] if not ruleFullDescription == "" else "N/A"}', "markdown": self.__getRuleHelpMarkdownMessage(issue)},
                            "properties": {"security-severity": self.__nativeSeverityToNumber(issue["severity"].lower()), "tags": self.__addTags(issue)},
                            "defaultConfiguration": {"level" : self.__nativeSeverityToLevel(issue["severity"].lower())}}
                    rules.append(rule)
                #Create a new result
                result = {}
                
                fullDescription = f'[See in Polaris]({issue["url"]})\n'
                if "description" in issue: fullDescription += f'{issue["description"]}\n\n'
                result['message'] = {"text": f'{fullDescription[:1000] if not fullDescription == "" else "N/A"}'}
                result['ruleId'] = rulesId
                lineNumber = f'{int(issue["line-number"]) if "line-number" in issue and issue["line-number"] is not None and not issue["line-number"] == "" and not issue["line-number"] == "null" else 1}'
                result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": issue["path"]},"region":{"startLine":int(lineNumber)}}}]
                result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{issue["issue-key"]}').encode(encoding='UTF-8')).hexdigest()}
                for event in sorted(issue['subevents'], key=lambda x: x['event-number']):
                    startline = f'{int(event["start-line"]) if "start-line" in event else int(lineNumber)}'
                    endline = f'{int(event["end-line"]) if "end-line" in event else startline}'
                    message = f'{event["mainevent_description"] if "mainevent_description" in event else event["support_description"]}'
                    locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri":issue["path"]},
                        "region":{"startLine": int(startline), "endLine": int(endline)}}, 
                        "message" : {"text": f'Event step {event["event-number"]}: {message}'}}})
                codeFlowsTable, loctionsFlowsTable = [], []
                threadFlows, loctionsFlows = {}, {}
                loctionsFlows['locations'] = locations
                loctionsFlowsTable.append(loctionsFlows)
                threadFlows['threadFlows'] = loctionsFlowsTable
                codeFlowsTable.append(threadFlows)
                result['codeFlows'] = codeFlowsTable
                issues.append(result)
            sarifIssues['results'] = issues
        else:
            logging.info(f'No issues found!')
        return sarifIssues, rules

    def __getRuleHelpMarkdownMessage(self, issue):
        messageText = ""
        messageText += f'{issue["description"] if issue["description"] else "N/A"}'
        if "local_effect" in issue and issue['local_effect']: messageText += f"\n\n## Local effect\n{issue['local_effect']}"
        if "remediation" in issue and issue["remediation"]: messageText += f'\n\n## Remediation\n{issue["remediation"]}\n\n'
        if "cwe" in issue and issue["cwe"]:
            messageText += f"\n\n## References\n"
            for cwe in issue["cwe"].split(','): 
                messageText += f"* Common Weakness Enumeration: [CWE-{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html)\n"
        return messageText

    def __addTags(self, issue):
        tags = []
        tags.append("security")
        tags.append("SAST")
        if "cwe" in issue and issue["cwe"]:
            for cwe in issue["cwe"].split(','): 
                tags.append(f'external/cwe/cwe-{cwe}')
        return tags

    def __nativeSeverityToLevel(self, argument): 
        switcher = { 
            "audit": "warning", 
            "high": "error", 
            "low": "note", 
            "medium": "warning"
        }
        return switcher.get(argument, "warning")

    def __nativeSeverityToNumber(self, argument): 
        switcher = { 
            "audit": "5.0", 
            "high": "8.9", 
            "low": "3.8", 
            "medium": "6.8"
        }
        return switcher.get(argument, "6.8")

    def getSarifJsonFooter(self, toolDriverName, rules):
        return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":"1.0.1","organization":"Synopsys","rules":rules}}


    def writeToFile(self, coverityFindingsInSarif):
        f = open(args.outputFile, "w")
        f.write(json.dumps(coverityFindingsInSarif, indent=3))
        f.close()

    def getIncrementalAnalysisIssues(self, previewFileName):
        previewData = None
        if ( exists(previewFileName) ):
            previewData = json.load(open(previewFileName, "r"))
        else:
            logging.error(f'file: {previewFileName} not found!')
        if previewData:
            issues = previewData["issues"]
            return issues


    def getIncrementalResults(self, previewFileName):
        cov_issues = self.getIncrementalAnalysisIssues(previewFileName)
        if cov_issues:
            results = {}
            sarifIssues = []
            rules = []
            ruleIds = []
            for cov_issue in cov_issues:
                ruleId = f'{cov_issue["checkerName"]}/{cov_issue["type"]}/{cov_issue["subtype"] if "subtype" in cov_issue else "_"}/{cov_issue["code-language"]}'
                sarifIssue = {"ruleId":ruleId}
                if not ruleId in ruleIds:
                    rule = {"id":ruleId, "shortDescription":{"text":cov_issue['checkerProperties']['subcategoryShortDescription']}, 
                        "fullDescription":{"text":f'{cov_issue["checkerProperties"]["subcategoryLongDescription"] if cov_issue["checkerProperties"]["subcategoryLongDescription"] else "N/A"}'},
                        "defaultConfiguration":{"level":self.__nativeSeverityToLevel(cov_issue['checkerProperties']['impact'].lower())}}
                    rules.append(rule)
                    ruleIds.append(ruleId)
                messageText = ""
                remediationText = ""
                lineNumber = ""
                locations = []
                for event in sorted(cov_issue['events'], key=lambda x: x['eventNumber']):
                    locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": event["strippedFilePathname"]},"region":{"startLine":f'{int(event["lineNumber"]) if event["lineNumber"] else 1}'}}, 
                        "message" : {"text": f'Event Set {event["eventTreePosition"]}: {event["eventDescription"]}'}}})
                    if event['main']: 
                        messageText = event['eventDescription']
                        lineNumber = event['lineNumber']
                    if event['events'] and len(event['events']) > 0:
                        for subevent in sorted(event['events'], key=lambda x: x['eventNumber']):
                            locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": event["strippedFilePathname"]},"region":{"startLine":f'{int(subevent["lineNumber"]) if subevent["lineNumber"] else 1}'}}, 
                                "message" : {"text": f'Event #{subevent["eventTreePosition"]}: {subevent["eventDescription"]}'}}})
                    if event['remediation']: remediationText = event['eventDescription']
                if not remediationText == "":
                    messageText += f'\nRemediation Advice: {remediationText}'
                sarifIssue['message'] = {"text": cov_issue["checkerName"] + ":" + messageText}
                sarifIssue['locations'] = [{"physicalLocation":{"artifactLocation":{"uri":cov_issue["strippedMainEventFilePathname"]},"region":{"startLine":f'{int(lineNumber) if lineNumber and not lineNumber == "" else 1}'}}}]
                sarifIssue['partialFingerprints'] = {"primaryLocationLineHash": cov_issue['mergeKey']}
                codeFlowsTable, loctionsFlowsTable = [], []
                threadFlows, loctionsFlows = {}, {}
                loctionsFlows['locations'] = locations
                loctionsFlowsTable.append(loctionsFlows)
                threadFlows['threadFlows'] = loctionsFlowsTable
                codeFlowsTable.append(threadFlows)
                sarifIssue['codeFlows'] = codeFlowsTable
                sarifIssues.append(sarifIssue)
            results['results'] = sarifIssues
            return results, rules
        else:
            logging.info(f'No issues found!')
            return {},{}

if __name__ == '__main__':
    try:
        start = timer()
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Get issues for a given scan job and prints out results in SARIF -format')
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="DEBUG")
        parser.add_argument('--url', default=os.getenv('POLARIS_SERVER_URL'), help='Polaris URL', required=True)
        parser.add_argument('--token', default=os.getenv('POLARIS_ACCESS_TOKEN'), help='Polaris Access Token', required=True)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/polarisFindings.sarif.json \
                                                    if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--jobid', help="Polaris scan jobId, if this is not give, then script will do the scan by using Polaris thin client.", default="")
        parser.add_argument('--project', help="Project name in Polaris", required=False)
        parser.add_argument('--branch', help="Branch name in Polaris", required=False)
        parser.add_argument('--status', help="Indicates which issues are returned based on the status, if not given, then all are returned. Options: opened,closed. ", required=False)
        parser.add_argument('--incremental_results', help="File name with full path for incremental analysis result.", required=False)
        args = parser.parse_args()
        #Initializing the logger
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=args.log_level)
        #Printing out the version number
        logging.info("Polaris results to SARIF formatter version: " + __versionro__)
        if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f'Given params are: {args}')
        results, rules = [],[]
        polarisSarifFormatter = PolarisResultsToSarif(args.url, args.token)
        if args.incremental_results:
            results, rules = polarisSarifFormatter.getIncrementalResults(args.incremental_results)
        else:
            if args.jobid:
                logging.debug(f'Getting all jobinfo for jobId: {args.jobid}')
                jobInfo = polarisSarifFormatter.getJobInfo(args.jobid)
                if jobInfo:
                    results, rules = polarisSarifFormatter.getResults(jobInfo)
            elif args.project and args.branch:
                projectId, branchId = polarisSarifFormatter.getProjectandBranchIds(args.project, args.branch)
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.debug(f'ProjectId is {projectId} for project with name: {args.project}')
                    logging.debug(f'BranchId is {branchId} for branch with name: {args.branch}')
                jobInfo = polarisSarifFormatter.getJobs(projectId,branchId)
                if jobInfo:
                    results, rules = polarisSarifFormatter.getResults(jobInfo)
        if results and len(results) > 0 and rules and len(rules) > 0:
            results['tool'] = polarisSarifFormatter.getSarifJsonFooter("Coverity on Polaris", rules)
            runs = []
            runs.append(results)
            sarif_json = polarisSarifFormatter.getSarifJsonHeader()
            sarif_json['runs'] = runs
            if args.outputFile:
                polarisSarifFormatter.writeToFile(sarif_json)
            else:
                print(json.dumps(sarif_json, indent=3))
        end = timer()
        logging.info(f"Creating SARIF format took: {end - start} seconds.")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)