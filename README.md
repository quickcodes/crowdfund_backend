// Used packages: uv add fastapi uvicorn sqlalchemy "passlib[bcrypt]" python-jose python-dotenv email-validator
// To run: uv run uvicorn app.main:app --reload
// uv add "bcrypt<4.0"


<!-- FastAPI → web framework (handles routing, requests, responses)

Uvicorn → ASGI server (runs the app)

SQLAlchemy → database ORM

Pydantic → request/response validation

Passlib + bcrypt → password hashing

python-jose → JWT tokens -->