# disable-inactive-iam-users-lambda #

[![GitHub Build Status](https://github.com/cisagov/disable-inactive-iam-users-lambda/workflows/build/badge.svg)](https://github.com/cisagov/disable-inactive-iam-users-lambda/actions)

This repository contains the code for an AWS Lambda function that
disables access for users who have not used said access sufficiently
recently.

## Building the base Lambda image ##

The base Lambda image can be built with the following command:

```console
docker compose build
```

This base image is used both to build a deployment package and to run the
Lambda locally.

## Building a deployment package ##

You can build a deployment zip file to use when creating a new AWS Lambda
function with the following command:

```console
docker compose up build_deployment_package
```

This will output the deployment zip file in the root directory.

## Running the Lambda locally ##

The configuration in this repository allows you run the Lambda locally for
testing as long as you do not need explicit permissions for other AWS
services. This can be done with the following command:

```console
docker compose up --detach run_lambda_locally
```

You can then invoke the Lambda using the following:

```console
 curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
```

The `{}` in the command is the invocation event payload to send to the Lambda
and would be the value given as the `event` argument to the handler.

Once you are finished you can stop the detached container with the following command:

```console
docker compose down
```

To customize the name of the deployment file, you can override the
`BUILD_FILE_NAME` environment variable.  For example:

```console
BUILD_FILE_NAME="disable_inactive_iam_users_lambda.zip" docker compose up build_deployment_package
```

## How to update Python dependencies ##

The Python dependencies are maintained using a [Pipenv](https://github.com/pypa/pipenv)
configuration for each supported Python version. Changes to requirements
should be made to the respective `src/py<Python version>/Pipfile`. More
information about the `Pipfile` format can be found [here](https://pipenv.pypa.io/en/latest/basics/#example-pipfile-pipfile-lock).
The accompanying `Pipfile.lock` files contain the specific dependency versions
that will be installed. These files can be updated like so (using the Python
3.9 configuration as an example):

```console
cd src/py3.9
pipenv lock
```

## Lambda inputs ##

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| expiration_days | A strictly positive integer denoting the number of days after which an IAM user's access is considered inactive if unused. | `number` | n/a | yes |

## Example Lambda input ##

The following is an example of the JSON input event that is expected by the
Lambda:

```json
{
    "expiration_days": 45
}
```

## Deploying the Lambda ##

The easiest way to deploy the Lambda and related resources is to use
the
[cisagov/disable-inactive-iam-users-terraform](https://github.com/cisagov/disable-inactive-iam-users-terraform)
repository.  Refer to the documentation in that project for more
information.

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
