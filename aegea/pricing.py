from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json
from datetime import datetime, timedelta

import requests

from . import register_parser
from .util import paginate
from .util.printing import format_table, page_output, tabulate, format_datetime
from .util.aws import region_name, get_pricing_data, offers_api, clients
from .util.compat import median

def pricing(args):
    table = []
    if args.offer == "spot":
        window_start = datetime.utcnow() - timedelta(hours=1)
        spot_prices, hours = {}, set()
        paginator = clients.ec2.get_paginator('describe_spot_price_history')
        filters = [dict(Name="product-description", Values=["Linux/UNIX"])]
        for line in paginate(paginator, StartTime=window_start, Filters=filters):
            hour = line["Timestamp"].replace(minute=0, second=0)
            hours.add(hour)
            spot_prices.setdefault(line["InstanceType"], {})
            spot_prices[line["InstanceType"]].setdefault(hour, [])
            spot_prices[line["InstanceType"]][hour].append(float(line["SpotPrice"]))
        for instance_type in sorted(spot_prices.keys()):
            prices = [spot_prices[instance_type].get(h) for h in sorted(hours)]
            prices = ["%.4f (max=%.4f, n=%d)" % (median(p), max(p), len(p)) if p else p for p in prices]
            table.append([instance_type] + prices)
        page_output(format_table(table,
                                 column_names=["InstanceType"] + [format_datetime(h) for h in sorted(hours)],
                                 max_col_width=args.max_col_width))
    elif args.offer:
        if args.region is None:
            args.region = clients.ec2.meta.region_name
        pricing_data = get_pricing_data(args.offer)
        required_attributes = dict(location=region_name(args.region))
        if args.offer == "AmazonEC2":
            args.columns += args.columns_ec2
            args.sort_by = "attributes.instanceType"
            required_attributes.update(tenancy="Shared", operatingSystem="Linux")
        elif args.offer == "AmazonRDS":
            args.columns += ["attributes.databaseEngine"] + args.columns_ec2
            args.sort_by = "attributes.databaseEngine"
        for product in pricing_data["products"].values():
            if not all(product["attributes"].get(i) == required_attributes[i] for i in required_attributes):
                continue
            ondemand_terms = list(pricing_data["terms"]["OnDemand"][product["sku"]].values())[0]
            product.update(list(ondemand_terms["priceDimensions"].values())[0])
            table.append(product)
        page_output(tabulate(table, args))
    else:
        offer_index = offers_api + "/aws/index.json"
        print("Choose from:", ", ".join(["spot"] + list(requests.get(offer_index).json()["offers"])))

parser = register_parser(pricing, help='List AWS prices')
parser.add_argument("offer", nargs="?", help="""
AWS product offer to list prices for. Run without this argument to see the list of available products.""")
parser.add_argument("--region")
parser.add_argument("--columns", nargs="+", default=["attributes.location", "unit", "pricePerUnit.USD", "description"])
parser.add_argument("--columns-ec2", nargs="+",
                    default=["attributes.instanceType", "attributes.vcpu", "attributes.memory", "attributes.storage"])
parser.add_argument("--sort-by")
