import os
import sys
from babel.messages import frontend as babel

def extract_messages():
    """Extract all messages from the project."""
    # Extract messages from Python files and templates
    extractor = babel.extract_messages()
    extractor.output_file = 'messages.pot'
    extractor.mapping_file = 'babel.cfg'
    extractor.input_paths = ['.']
    extractor.initialize_options()
    extractor.finalize_options()
    extractor.run()

def init_catalog(lang):
    """Initialize message catalog for a specific language."""
    if not os.path.exists('messages.pot'):
        print("Error: messages.pot file not found. Run extract_messages first.")
        return
    
    # Create the locale directory if it doesn't exist
    locale_dir = os.path.join('translations', lang, 'LC_MESSAGES')
    os.makedirs(locale_dir, exist_ok=True)
    
    # Initialize the catalog
    init = babel.init_catalog()
    init.locale = lang
    init.input_file = 'messages.pot'
    init.output_file = os.path.join(locale_dir, 'messages.po')
    init.initialize_options()
    init.finalize_options()
    init.run()

def compile_catalogs():
    """Compile all message catalogs."""
    compiler = babel.compile_catalog()
    compiler.directory = 'translations'
    compiler.initialize_options()
    compiler.finalize_options()
    compiler.run()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_messages.py [extract|init|compile] [lang]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'extract':
        extract_messages()
    elif command == 'init' and len(sys.argv) > 2:
        init_catalog(sys.argv[2])
    elif command == 'compile':
        compile_catalogs()
    else:
        print("Invalid command or missing language code")
        sys.exit(1)
