from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json

import boto3, requests

from . import register_parser
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import region_names, get_pricing_data, offers_api

def pricing(args):
    if args.offer:
        table = []
        if args.region is None:
            args.region = boto3.client("ec2").meta.region_name
        pricing_data = get_pricing_data(args.offer)
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
