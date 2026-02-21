# System Overview Diagram

```mermaid
graph LR
    Sensors --> Filebeat
    Filebeat --> Elasticsearch
    Elasticsearch --> FeatureEngine
    FeatureEngine --> DetectionEngine
    DetectionEngine --> API
    API --> Dashboard
```
