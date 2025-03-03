# Sentinel 

The project is an adaptation of threat intelligence on collaborative efforts with incentive based approch. the project is loosely based on threat intel which is often extracted and shared across the internet in a way that the same needs to be quite have a standard. Here we are trying to achieve those

##### To run

1. pip install -r requirments.txt
2. flask db init
3. flask db migrate -m "Intiial migration"
4. flask db upgrade


now run the application with

`python run.py`



Threats                          Organization                                       Org-affteted

Ubuntu 24.04                      Deloitte - Srv 1 - Ubuntu 18
                                  Dell - Srv 2 - Ubutuntu 24.04                   Dell Srv2 is affected

### Mapping out all the endpoints related to CRUD Operation

Benign an application that have lots of crud operations, the backend will be just a translator and a gatekeeper within client and DB with respect to the ops and sec respectively

Major Routes 

/   -> Main Route ( Threat Page )

/ Auth -> Everything related to authentication

/ Admin -> Admin related activites

/ org   -> organization realated applications

| Sl No | Route                              | Methods    | Category          | Use of Endpoint                                      | Remarks                                   | Implemented |
|-------|------------------------------------|------------|-------------------|------------------------------------------------------|-------------------------------------------|-------------|
| 1     | /                                  | GET        | Major Routes      | Main Route (Threat Page)                             |                                           | ✅          |
| 2     | /auth                              | -          | Major Routes      | Base route for authentication                        |                                           | ✅          |
| 3     | /admin                             | -          | Major Routes      | Base route for admin activities                      |                                           | ✅          |
| 4     | /org                               | -          | Major Routes      | Base route for organization applications             |                                           | ✅          |
| 5     | /threat                            | GET        | Major Routes      | Submit report                                        |                                           | ✅          |
| 6     | /all                               | GET        | Major Routes      | View all reports                                     |                                           | ✅          |
| 7     | /submit-threat                     | POST       | Major Routes      | Submit threat endpoint                               |                                           | ✅          |
| 8     | /auth/register                     | GET, POST  | Authentication    | Register any user                                    |                                           | ✅          |
| 9     | /auth/login                        | GET, POST  | Authentication    | Login into the application                           |                                           | ✅          |
| 10    | /auth/logout                       | GET, POST  | Authentication    | Logout of the application                            |                                           | ✅          |
| 11    | /auth/companylogin                 | GET, POST  | Authentication    | Company login page                                   |                                           | ✅          |
| 12    | /admin                             | GET        | Admin             | Admin Dashboard                                      |                                           | ✅          |
| 13    | /admin/approve-threat/<int>        | POST       | Admin             | Approve a specific threat                            |                                           | ✅          |
| 14    | /admin/reject-threat/<int>         | POST       | Admin             | Reject a specific threat                             |                                           | ✅          |
| 15    | /admin/delete_threat/<int>         | POST       | Admin             | Delete a specific threat                             | (Typo corrected from "Deltes")            | ✅          |
| 16    | /admin/retain_threat/<int>         | POST       | Admin             | Restore a specific threat                            |                                           | ✅          |
| 17    | /admin/user/<int>/approve          | POST       | Admin             | Approve a user for a specific company                | [To Implement]                            |             |
| 18    | /admin/user/<int>/revoke           | POST       | Admin             | Revoke a user’s access to a company                  | [To Implement]                            |             |
| 19    | /admin/user/<int>/ban              | POST       | Admin             | Remove a user from the system                        | [To Implement, controlled by role]        |             |
| 20    | /admin/org/add/                    | GET, POST  | Admin             | Add a new organization                               | [To Implement]                            |             |
| 21    | /admin/org/ban/<int>               | POST       | Admin             | Ban an organization                                  | [To Implement]                            |             |
| 22    | /admin/org/deban/<int>             | POST       | Admin             | De-ban an organization                               | [To Implement]                            |             |
| 23    | /org/create                        | POST       | Organization      | Create an organization                               | [Should be ported to admin routes]        | ✅          |
| 24    | /org/list                          | GET        | Organization      | Get all assets within an organization                | [Should be ported to admin routes]        | ✅          |
| 25    | /org/create_assset                 | POST       | Organization      | Create assets within an organization                 |                                           | ✅          |
| 26    | /org/<int:org_id>/assets           | GET        | Organization      | Retrieve assets within an organization               | [Beware of IDOR]                          | ✅          |
| 27    | /org/validate                      | TBD        | Organization      | Check vulnerabilities against existing threats       | [To Implement]                            |             |
| 28    | /org/generate_report               | TBD        | Organization      | Generate a report                                    | [To Implement, AI Module]                 |             |
| 29    | /org/chat                          | TBD        | Organization      | RAG based chat functionality                         | [To Implement, AI Module]                 |             |
| 30    | /org/add_excel                     | TBD        | Organization      | Add data to DB from Excel file                       | [To Implement, External Module]           |             |
