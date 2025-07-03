from app import app, db, create_tables, socketio

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    
    # Run the Socket.IO server
    socketio.run(
        app,
        host='0.0.0.0',
        port=5001,  # Changed from 5000 to 5001
        debug=True,
        use_reloader=True,
        log_output=True
    )
