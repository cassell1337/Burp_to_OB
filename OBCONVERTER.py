# Burp imports
from burp import IBurpExtender, ITab, IContextMenuFactory
import re
# Jython specific imports for the GUI
from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList

# stdlib
import sys
import threading

# For easier debugging, if you want.
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # Set our extension name
        self.callbacks.setExtensionName("Burp request Convert to OB2")

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create a split panel
        splitPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        # Create the top panel containing the text area
        box = swing.Box.createVerticalBox()

        # Make the text area
        row = swing.Box.createHorizontalBox()
        textPanel = swing.JPanel()
        self.textArea = swing.JTextArea('', 15, 100)
        self.textArea.setLineWrap(True)
        scroll = swing.JScrollPane(self.textArea)
        row.add(scroll)
        box.add(row)

         # Make a button
        row = swing.Box.createHorizontalBox()
        row.add(swing.JButton('Convert!', 
                          actionPerformed=self.handleButtonClick))
        box.add(row)

        # Set the top pane
        splitPane.setTopComponent(box)

        # Bottom panel for the response. 
        box = swing.Box.createVerticalBox()

        # Make the text box for the HTTP response
        row = swing.Box.createHorizontalBox()
        self.responseTextArea = swing.JTextArea('', 15, 100)
        self.responseTextArea.setLineWrap(True)
        scroll = swing.JScrollPane(self.responseTextArea)
        row.add(scroll)
        box.add(row)

        # Set the bottom pane
        splitPane.setBottomComponent(box)

        # Start the divider roughly in the middle
        splitPane.setDividerLocation(250)

        # Add everything to the custom tab
        self.tab.add(splitPane)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Convert TO OB2"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        """Adds the extension to the context menu that 
        appears when you right-click an object.
        """
        self.context = invocation
        itemContext = invocation.getSelectedMessages()
        
        # Only return a menu item if right clicking on a 
        # HTTP object
        if itemContext > 0:
        
            # Must return a Java list 
            menuList = ArrayList()
            menuItem = swing.JMenuItem("Convert to ob2",
                                        actionPerformed=self.handleHttpTraffic)
            menuList.add(menuItem)
            return menuList
        return None

    def handleHttpTraffic(self, event):
        """Calls the function to write the HTTP object to 
        the request text area, and then begins to parse
        the HTTP traffic for use in other functions.
        """

        # Writes to the top pane text box
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()

    def writeRequestToTextBox(self):
        """Writes HTTP context item to RequestTransformer 
        tab text box.
        """
        httpTraffic = self.context.getSelectedMessages()
        httpRequest = [item.request.tostring() for item in httpTraffic]
        request = ''.join(httpRequest)
        self.textArea.text = request

    def handleButtonClick(self, event):
        """Attempts to make an HTTP request for the
        object in the text area.
        """

        # Get data about the request that was right clicked
        host = self.httpService.host 
        port = self.httpService.port
        protocol = self.httpService.protocol
        # protoChoice = True if protocol.lower() == 'https' else False

        # Parse the text area that should contain an HTTP
        # request.
        requestInfo = self.helpers.analyzeRequest(self.textArea.text)
        #get headers
        headers = str(requestInfo.getHeaders())
        # get body
        bodyOffset = requestInfo.bodyOffset 
        body = self.textArea.text[bodyOffset:]
        # do the ob convert under here
        headers1 = "Host: "+headers.split('Host: ')[1].split(', Cookie: ')[0]
        try:
            cookies1 = headers.split('Cookie: ')[1][:-1]
        except IndexError:
            cookies1 = ""
        #print cookies1
        # make url
        gg = headers.split(', ')[0].replace("[", "").split(' ')
        method = gg[0]
        dom = gg[1]
        url = protocol + '://' + host + dom
        ll = "BLOCK:HttpRequest\n"
        ll = ll + "LABEL:REQUEST\n"
        ll = ll + '  url = "{str(url)}"\n'
        ll = ll + "  method = {str(methodd)}\n"
        ll = ll + '  customCookies = {str(self.makecookies(cookies1))}\n'
        ll = ll + '  customHeaders = {str(self.makeheaders(headers1))}\n'
        ll = ll + "  TYPE:STANDARD\n"
        ll = ll + '  $"{str(body)}"\n'
        ll = ll + '  "fxdcbfgnxfxgn"\n'
        ll = ll + "ENDBLOCK\n"
        ll = ll.replace("{str(url)}", url)
        ll = ll.replace("{str(methodd)}", method)
        ll = ll.replace("{str(self.makecookies(cookies1))}", self.makecookies(cookies1))
        ll = ll.replace("{str(self.makeheaders(headers1))}", self.makeheaders(headers1))
        ll = ll.replace("{str(body)}", body)
        ll = ll.replace("fxdcbfgnxfxgn", self.getcontenttype(headers1))
        self._decodedAuthorizationHeader = str(ll)
        self.responseTextArea.text = self._decodedAuthorizationHeader
    def getcontenttype(self, data):
        data1 = data.split(', ')
        for x in data1:
            if "Content-Type" in x:
                contenttype = x.split(": ")[1]
                return contenttype
        return "application/x-www-form-urlencoded"
    def makeheaders(self, data):
        data1 = data.split(', ')
        newhead = "{"
        for x in data1:
            if "Content-Length" not in x and "Content-Type" not in x:
                try:
                    #print x
                    x1 = x.split(": ")
                    #print x1
                    if '"' in str(x[1]):
                        newhead = newhead + '("' + str(x1[0]) + '", "' + str(x1[1]).replace('"', '\\"')+'"),'
                    else:
                        newhead = newhead + '("' + str(x1[0]) + '", "' + str(x1[1]) + '"),'
                except Exception as e:
                    pass
                    #print e
        newhead = newhead[:-1]
        newhead = newhead + "}"
        return newhead

    def makecookies(self, data):
        if data != "":
            try:
                data = data.split(',')[0]
            except:
                pass
            data = data.split('; ')
            newcook = "{"
            for x in data:
                x = x.split("=")
                if '"' in str(x[1]):
                    newcook = newcook + '("'+str(x[0])+'", "'+str(x[1]).replace('"', '\\"')+'"),'
                else:
                    newcook = newcook + '("' + str(x[0]) + '", "' + str(x[1]) + '"),'
            newcook = newcook[:-1]
            newcook = newcook + "}"
            return newcook
        else:
            return "{}"

try:
    FixBurpExceptions()
except:
    pass