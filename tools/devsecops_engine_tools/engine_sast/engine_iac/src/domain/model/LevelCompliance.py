class LevelCompliance:
    def __init__(self, data):
        self.critical = data.get("Critical")
        self.high = data.get("High")
        self.medium = data.get("Medium")
        self.low = data.get("Low")
        self.unknown = data.get("Unknown")
