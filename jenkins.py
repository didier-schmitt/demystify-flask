#!/usr/bin/env python

import requests

class JenkinsHelper:
    jenkins_url = 'http://ci.localhost'

    def __init__(self, token):
        self.token = token
    
    def build(self, job):
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token
        }
        endpoint = '%s/job/%s/build' % (self.jenkins_url, job)
        response = requests.post(endpoint, headers=headers)
        if response.status_code == 201:
            # Job launched in Build Queue
            endpoint = '%sapi/json' % response.headers['Location'] 
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                j = response.json()
                return j['id']
            else:
                return None
        else:
            # Something has gone wrong...
            return None
    
    def status(self, id):
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token
        }
        endpoint = '%s/queue/item/%s/api/json' % (self.jenkins_url, id)
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            j = response.json()
            if 'cancelled' in j and j['cancelled'] == True:
                return 'Aborted'
            if 'stuck' in j and j['stuck'] == True:
                return 'Stuck'
            if 'executable' in j:
                endpoint = '%sapi/json' % j['executable']['url']
                response = requests.get(endpoint, headers=headers)
                if response.status_code == 200:
                    j = response.json()
                    if j['building'] == True:
                        return 'Running'
                    if j['result'] ==  'SUCCESS':
                        return 'Succeeded'
                    if j['result'] ==  'FAILURE':
                        return 'Failed'
                    if j['result'] ==  'ABORTED':
                        return 'Aborted'
                else:
                    return None
            else:
                return 'Pending'
        else:
            return None 