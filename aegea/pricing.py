from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json

import boto3, requests

from . import register_parser, config
from .util.printing import format_table, page_output, get_field, get_cell, tabulate

offers_api = "https://pricing.us-east-1.amazonaws.com/offers/v1.0"
region_ids = {
    "US East (N. Virginia)": "us-east-1",
    "US West (N. California)": "us-west-1",
    "US West (Oregon)": "us-west-2",
    "EU (Ireland)": "eu-west-1",
    "EU (Frankfurt)": "eu-central-1",
    "Asia Pacific (Tokyo)": "ap-northeast-1",
    "Asia Pacific (Seoul)": "ap-northeast-2",
    "Asia Pacific (Singapore)": "ap-southeast-1",
    "Asia Pacific (Sydney)": "ap-southeast-2",
    "South America (Sao Paulo)": "sa-east-1",
    "AWS GovCloud (US)": "us-gov-west-1",
}
region_names = {v: k for k, v in region_ids.items()}

def get_pricing_data(offers_api, offer):
    offer_filename = os.path.join(config._config_dir, offer + ".json")
    try:
        # FIXME: expire old data
        with open(offer_filename) as fh:
            pricing_data = json.load(fh)
    except Exception:
        url = offers_api + "/aws/{offer}/current/index.json".format(offer=offer)
        pricing_data = requests.get(url).json()
        try:
            with open(offer_filename, "w") as fh:
                json.dump(pricing_data, fh)
        except Exception as e:
            print(e, file=sys.stderr)
    return pricing_data

def pricing(args):
    if args.offer:
        table = []
        if args.region is None:
            args.region = boto3.client("ec2").meta.region_name
        pricing_data = get_pricing_data(offers_api, args.offer)
        for product in pricing_data["products"].values():
            required_attributes = {}
            if args.offer == "AmazonEC2":
                required_attributes = dict(location=region_names[args.region],
                                           tenancy="Shared",
                                           operatingSystem="Linux")
            if not all(product["attributes"].get(i) == required_attributes[i] for i in required_attributes):
                continue
            ondemand_terms = list(pricing_data["terms"]["OnDemand"][product["sku"]].values())[0]
            product.update(list(ondemand_terms["priceDimensions"].values())[0])
            table.append(product)
        page_output(tabulate(table, args))
    else:
        offer_index = offers_api + "/aws/index.json"
        print("Choose from:", ", ".join(requests.get(offer_index).json()["offers"]))

parser = register_parser(pricing, help='List AWS prices')
parser.add_argument("offer", nargs="?")
parser.add_argument("--region")
parser.add_argument("--columns", nargs="+", default=["attributes.location", "attributes.instanceType", "attributes.vcpu", "attributes.memory", "attributes.storage", "pricePerUnit.USD"])
parser.add_argument("--sort-by", default="attributes.instanceType")
