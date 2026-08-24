# Architettura

## C4 Model (PlantUML)

I diagrammi C4 descrivono contesto e componenti principali. I sorgenti sono in `docs/diagrams/`.

### System Context

```plantuml
!include diagrams/c4-context.puml
```

### Container Diagram

```plantuml
!include diagrams/c4-container.puml
```

## Note implementative

- FastAPI gestisce UI, API, autenticazione e rate limit.
- Celery orchestration per esecuzioni parallele.
- SQLite per persistenza rapida; compatibile con migrazione verso PostgreSQL.
