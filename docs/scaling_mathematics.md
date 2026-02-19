# Scaling Mathematics

*Horizontal scaling capacity plans for 1k to 100k req/sec.*

## 1. Resource Models (Per Instance)

- **Log Ingestion**: 500 req/s
- **Detection**: 200 req/s (ML bottleneck)
- **Risk Scoring**: 300 events/s

## 2. Capacity Plan: 10,000 req/sec

| Service | Instances Required | Calculation |
|---|---|---|
| Ingestion | 24 | $(10,000 \times 1.2) / 500$ |
| Detection | 60 | $(10,000 \times 1.2) / 200$ |
| Risk Scorer | 6 | $(12,000 \times 0.15 \text{ alert rate}) / 300$ |
| **Total** | **90** | — |

## 3. Cost Modeling

- **Instance Cost**: $50/month
- **Monthly Cost (10k scale)**: $4,500 (Compute) + $1,300 (Storage/Infra) = **$5,800/month**
- **Cost per Million Hits**: **$0.22**

## 4. Strategic Bottleneck

The **Detection Engine** accounts for 66% of the compute footprint. Optimizing the Python/ML inference layer by 2x would save $1,500/month.
