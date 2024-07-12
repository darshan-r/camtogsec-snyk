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

temp = 5
for v in issue_set.issues:
    temp -= 1
    if temp == 0:
        break
    
    print(f'id = {v.id}')
    print(f'issueType = {v.issueType}')
    print(f'pkgName = {v.pkgName}')
    print(f'pkgVersions = {v.pkgVersions}')
    # print(f'issueData = {v.issueData}')
    print(f'isPatched = {v.isPatched}')
    print(f'isIgnored = {v.isIgnored}')
    # print(f'fixInfo = {v.fixInfo}')
    print(f'introducedThrough = {v.introducedThrough}')
    print(f'ignoreReasons = {v.ignoreReasons}')
    print(f'priorityScore = {v.priorityScore}')
    print(f'priority = {v.priority}')

    #Issue data
    print(f'id = {v.issueData.id}')
    print(f'title = {v.issueData.title}')
    print(f'severity = {v.issueData.severity}')
    print(f'url = {v.issueData.url}')
    print(f'exploitMaturity = {v.issueData.exploitMaturity}')
    print(f'description = {v.issueData.description}')
    print(f'identifiers = {v.issueData.identifiers}')
    print(f'credit = {v.issueData.credit}')
    print(f'semver = {v.issueData.semver}')
    print(f'publicationTime = {v.issueData.publicationTime}')
    print(f'disclosureTime = {v.issueData.disclosureTime}')
    print(f'CVSSv3 = {v.issueData.CVSSv3}')
    print(f'cvssScore = {v.issueData.cvssScore}')
    print(f'cvssDetails = {v.issueData.cvssDetails}')
    print(f'language = {v.issueData.language}')
    print(f'patches = {v.issueData.patches}')
    print(f'nearestFixedInVersion = {v.issueData.nearestFixedInVersion}')
    print(f'ignoreReasons = {v.issueData.ignoreReasons}')

    print('-----------------------------------------------------')

    # for the excel output
    # new_output_item = {
    #     "title": v.issueData.title,
    #     "id": v.id,
    #     "url": v.issueData.url,
    #     "package": "%s@%s" % (v.pkgName, v.pkgVersions),
    #     "severity": v.issueData.severity,
    #     "cvssScore": v.issueData.cvssScore,
    # }
    # lst_output.append(new_output_item)


# output_excel(lst_output, "snyk_aggregator_output.xlsx")