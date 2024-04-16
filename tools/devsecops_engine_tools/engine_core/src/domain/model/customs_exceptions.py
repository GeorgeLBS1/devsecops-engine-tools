class ExceptionVulnerabilityManagement(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class ExceptionFindingsRiskAcceptance(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class ExceptionGettingFindings(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
