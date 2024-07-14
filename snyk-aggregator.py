import xlsxwriter
from snyk import SnykClient
from datetime import datetime


snyk_token = 'YOUR SYNK API KEY'
org_id = 'YOUR ORG ID'

def output_excel(vulns, output_path):
    excel_workbook = xlsxwriter.Workbook(output_path)
    excel_worksheet = excel_workbook.add_worksheet()
    format_bold = excel_workbook.add_format({"bold": True})

    row_index = 0

    col_index = 0
    lst_col_headers = list(vulns[0].keys())

    for ch in lst_col_headers:
        excel_worksheet.write(
            row_index, col_index, lst_col_headers[col_index], format_bold
        )
        col_index += 1

    for v in vulns:
        row_index += 1

        col_index = 0
        for k in lst_col_headers:
            excel_worksheet.write(row_index, col_index, v[k])
            col_index += 1

    excel_workbook.close()

rest_client = SnykClient(snyk_token, version="2024-06-21", url="https://api.snyk.io/rest")

params = {"limit": 100}
all_orgs = rest_client.get_rest_pages(f"orgs", params=params)

lst_output = []
for org in all_orgs:
    issues = rest_client.get_rest_pages(f"orgs/{org['id']}/issues", params=params)

    for issue in issues:
        new_output_item = {
            "Issue_Title": issue['attributes']["title"],
            "Severity": issue['attributes']["effective_severity_level"],
            "Introduced_Date": datetime.strptime(issue['attributes']["created_at"], "%Y-%m-%dT%H:%M:%SZ"),
            "Issue_Status": issue['attributes']["status"],
            "Org_Name": org["attributes"]["name"],
        }
        lst_output.append(new_output_item)

output_excel(lst_output, "snyk_aggregator_output.xlsx")