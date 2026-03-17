# Quortax Harvester

Microserviço OSINT para o Quortax Hub. Wrapper FastAPI em torno do theHarvester.

## Endpoints

| Método | Rota | Descrição |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/scan` | Executar scan OSINT num domínio |
| GET | `/sources` | Listar fontes disponíveis |

## Exemplo de uso

```bash
curl -X POST https://seu-servico.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "empresa.com.br", "sources": "all", "limit": 100}'
```

## Fontes sem API key

- crtsh, dnsdumpster, hackertarget, rapiddns, otx, threatminer, urlscan, certspotter
