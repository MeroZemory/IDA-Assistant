# IDA Assistant

IDA Assistant is an IDA Pro plugin that leverages Anthropic's Claude-3-7 model to assist users in reverse engineering and binary analysis tasks. This project is a fork of [stuxnet147/IDA-Assistant](https://github.com/stuxnet147/IDA-Assistant), enhanced with the latest Claude-3-7-sonnet model and various performance improvements.

[한국어 README](README_KR.md)

## Key Features

- **Claude-3-7-sonnet Model Support**: Utilizes the latest Claude-3-7-sonnet model for more accurate and useful analysis results
- **Improved System Prompt**: 
  - Enhanced prompt structure with clear sections and better organization
  - Optimized command usage instructions to prevent common errors
  - Improved response format guidelines for better AI outputs
- **Token Management System**: 
  - Automatic token counting and message length management
  - Automatic removal of older messages when prompt length exceeds limits
- **Conversation Interruption**: UI for stopping analysis at any time during the conversation
- **Enhanced Function Name Search**: Similarity-based function name matching and suggestions using the fuzzywuzzy library
- **Strengthened Error Handling**: 
  - Automatic retry mechanism for API rate limit errors
  - Improved error handling for various exception scenarios
- **IDA Pro Integration**: 
  - Disassembly retrieval
  - Function decompilation
  - Address renaming
  - Function start/end address retrieval
  - Address lookup by name
  - Cross-reference analysis (xrefs)
  - Adding comments to addresses

## Installation

### Clone the repository:
```sh
git clone https://github.com/MeroZemory/IDA-Assistant.git
```

### Install dependencies:
```sh
pip install anthropic fuzzywuzzy
```

### Configuration:
1. Open the `IDA_Assistant.py` file and replace `api_key="YOUR API KEY"` with your actual Anthropic(Claude) API key.
2. Copy the `IDA_Assistant.py` file to your IDA Pro plugins directory.
3. Launch IDA Pro and enable the "IDA Assistant" plugin from the "Edit" menu.

## Usage

1. Press Alt+F1 or go to "Edit" > "Plugins" > "IDA Assistant" to open the assistant window.
2. Type your query or request in the input field and click "Send" or press Enter.
3. The AI assistant will analyze your query, execute relevant commands, and provide helpful suggestions and information.
4. To stop the analysis during conversation, click the "Stop" button.
5. Review the assistant's response in the chat history and follow the provided guidance to aid your reverse engineering process.
6. Continue the conversation with the assistant as needed, refining your queries and exploring different aspects of binary analysis.

## Recent Updates

- **March 2025**: 
  - Restructured system prompt for better organization and clarity
  - Improved command documentation and usage instructions
  - Enhanced response format guidelines for more useful AI outputs
- Updated to Claude-3-7-sonnet-latest model for improved analysis performance
- Added token counting and automatic message length management
- Implemented conversation interruption feature (Stop button)
- Enhanced function name search using the fuzzywuzzy library
- Strengthened retry mechanism and error handling logic

## Acknowledgments

- The system prompt used in this plugin was inspired by the AutoGPT project.
- The query functions were adapted from the Gepetto IDA Pro plugin.
- Original project: [stuxnet147/IDA-Assistant](https://github.com/stuxnet147/IDA-Assistant)

## License

This project is licensed under the MIT License.
