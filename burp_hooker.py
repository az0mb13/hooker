from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if not messageIsRequest:
            return
        request = message.getRequest()
        requestInfo = self.helpers.analyzeRequest(request)
        headers = requestInfo.getHeaders()
        body = request[requestInfo.getBodyOffset():].tostring()
        newbody = self.helpers.stringToBytes("data=demnboi")
        print(newbody)
        print(newbody.tostring())
        # print(self.helpers.stringToBytes(body))
        # for i in range(len(headers)):
        #     if headers[i].startswith('Language: en'):
        #         headers[i] = 'Language: de'
        # body = request[requestInfo.getBodyOffset():]
        updatedRequest = self.helpers.buildHttpMessage(headers, body)
        message.setRequest(updatedRequest)

# Work in progress