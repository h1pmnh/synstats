# synstats
Used to pull a summary CSV of an SRT's statistics on the Synack Red Team platform

# WARNING
These statistics will by default contain the vulnerability title. Please ensure that you are appropriately securing information retrieved with this API and should be running it only on the LP+ platform.

Please observe the rules for API throttling and feel free to modify the code appropriately to your needs, contributions in the form of pull requests are welcome.

# Installation

This library depends on the [synackAPI](https://github.com/gexpose/synackAPI) module, which is maintained by lvl0x0 and other key community members. This tool won't work unless the module is correctly installed and configured. We won't include installation instructions for the Synack API module here.

# Usage

Simply run the command as follows:

`python -u synstats.py`

Assuming you have your Synack Python API module correctly configured, you should see a CSV created with the following columns in it:

```
id	created_at	title	amount	category	subcategory	target	cvss	quality	created_at	resolved_at
```

The file will contain by default only `accepted` vulnerabilities. You are welcome to adjust the code to pull all your reported vulnerabilities if you would prefer.

