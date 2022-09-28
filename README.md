# Description
Generate temporary AWS STS credentials based on a preconfigured AWS profile.
New credentials will be saved fresh/overwrite in the form of a child AWS profile.
Script requires several parameters to be configured for it to work otherwise it may not work.

# How to execute
```
pipenv install
pipenv run python script.py -h
pipenv run python .\script.py -s arn:aws:iam::112233445566:mfa/user -pp parent_profile_name -cp child_profile_name -t 123456
```
