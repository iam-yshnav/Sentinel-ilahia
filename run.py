from app import create_app # calls app.py

app = create_app()

if __name__ == "__main__": # Entry point
    app.run(debug=True) 