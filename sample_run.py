import json
from pathlib import Path
from typing import List
from maltools.models import MaltoolFile, PowerShellFile, Maltool
from tqdm import tqdm

# Config
FILES_PATH = '/Path/To/For/Example/PowerSploit'

# Metadata
tool_name = 'PowerSploit'
tool_url = 'https://github.com/PowerShellMafia/PowerSploit'
tool_version = 'd943001'
tool_description = (
    'PowerSploit is a collection of Microsoft PowerShell modules that can be used to '
    'aid penetration testers during all phases of an assessment.'
)

# Read .ps1 files from a system path
path = Path(FILES_PATH)
files = list(path.glob('**/*.ps1'))

# MaltoolFile list
tool_files: List[MaltoolFile] = list()

# For each .ps1 file
for ps_file in tqdm(files):
    ps_file_url = f'{tool_url}/raw/master/{ps_file.relative_to(path)}'
    tool_files.append(PowerShellFile.parse(ps_file, ps_file_url))

# Add an extra file without any indicators but a higher risk score
tool_files.append(MaltoolFile(
    name='non-powershell.txt',
    url='http://example.com',
    sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    risk_score=8,
))

# Final tool
tool = Maltool(
    name=tool_name,
    url=tool_url,
    version=tool_version,
    description=tool_description,
    files=tool_files,
)

print(json.dumps(json.loads(tool.json()), indent=4))
print('\n## Summary ##')
print(f'Tool name: {tool.name}')
print(f'Overall tool risk score: {tool.risk_score}')

if tool.files:
    print(f'File count: {len(tool.files)}')
    indicator_count = 0

    for file in tool.files:
        if file.indicators:
            indicator_count += len(file.indicators)

    print(f'Indicator count: {indicator_count}')
