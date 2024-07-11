import xlsxwriter
from snyk import SnykClient


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


client = SnykClient(snyk_token)
all_projects = client.organizations.get(org_id).projects.all()

for project in all_projects:
    issue_set = project.issueset_aggregated.all()

lst_output = []
for v in issue_set.issues:
    print("\n %s" % v.issueData.title)
    print("  id: %s" % v.id)
    print("  url: %s" % v.issueData.url)

    print("  %s@%s" % (v.pkgName, v.pkgVersions))
    print("  Severity: %s" % v.issueData.severity)
    print("  CVSS Score: %s" % v.issueData.cvssScore)

    # print CVSS assigners if exists
    for detail in v.issueData.cvssDetails:
        print("    %s score: %s" % (detail['assigner'], detail['cvssV3BaseScore']))

    # for the excel output
    new_output_item = {
        "title": v.issueData.title,
        "id": v.id,
        "url": v.issueData.url,
        "package": "%s@%s" % (v.pkgName, v.pkgVersions),
        "severity": v.issueData.severity,
        "cvssScore": v.issueData.cvssScore,
    }
    lst_output.append(new_output_item)


output_excel(lst_output, "snyk_aggregator_output.xlsx")