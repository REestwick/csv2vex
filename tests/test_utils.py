import pytest
from csv2vex import utils
import pandas as pd
from cyclonedx.model import Property, Tool, XsUri
from cyclonedx.model.vulnerability import VulnerabilityCredits, BomTarget, BomTargetVersionRange, VulnerabilityAdvisory, VulnerabilityRating, VulnerabilitySource, VulnerabilitySeverity,VulnerabilityScoreSource, VulnerabilityReference, Vulnerability,  VulnerabilityAnalysis
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
import decimal
from cyclonedx.model.impact_analysis import ImpactAnalysisState, ImpactAnalysisJustification
from datetime import datetime
from pprint import pprint

def test_cwe():
    cwes_in = "[CWE-123, 456]"
    cwes_out = [123, 456]
    res = utils.get_cwes(cwes_in)
    assert res == cwes_out

def test_property():
    input_str = "check"
    output = Property(name="check", value="pass")
    input_data = pd.Series({"check": "pass"})
    res = utils.get_property(input_data, input_str)
    assert res == output

def test_tool():
    test_data = pd.Series(
                                {
                                    "tool_name": "Tool",
                                    "tool_version":"1.2.3"
                                }
                            )
    test_config = {'name':"tool_name", 'version':"tool_version"}

    out = Tool(name="Tool", version="1.2.3")

    res = utils.get_tool(test_data, test_config)
    assert res == out

def test_credit():
    test_config = {
        "organizations": [
            {
                "bom-ref": None,
                "name": "orgname",
                "urls": "orgurl",
                "contact": [
                    {
                        "bom-ref": None,
                        "name": "orgcontactname",
                        "email": "orgcontactemail",
                        "phone": "orgcontactphone"
                    }
                ]
            }
        ],
        "individuals": [
            {
                "bom-ref": None,
                "name": "individualname",
                "email": "individualemail",
                "phone": "individualphone"
            }
        ]
    }

    test_data = pd.Series(
                            {
                                "orgname":"OrgName",
                                "orgurl":"https://www.google.com/",
                                "orgcontactname":"Name",
                                "orgcontactemail":"example_email@email.com",
                                "orgcontactphone":"222-222-2222",
                                "individualname":"Name2",
                                "individualemail":"example_email@email.com",
                                "individualphone":"222-222-2222"

                            }
                        )
    
    out = VulnerabilityCredits(
                                organizations=[
                                                    OrganizationalEntity(
                                                                            name="OrgName",
                                                                            urls="https://www.google.com/",
                                                                            contacts=[
                                                                                OrganizationalContact(
                                                                                    name="Name",
                                                                                    email="example_email@email.com",
                                                                                    phone="222-222-2222"
                                                                                )
                                                                            ]
                                                                        )
                                            ], 
                                individuals=[
                                                    OrganizationalContact(
                                                                            name="Name2",
                                                                            email="example_email@email.com",
                                                                            phone="222-222-2222"
                                                                        )
                                            ]
                            )
    
    res = utils.get_credits(test_data, test_config)
    print(res)
    print(out)
    assert res.organizations[0].name == out.organizations[0].name

def test_affect():
    # output = {
    #             "affects": [
    #                             {
    #                                 "ref": "example/123",
    #                                 "versions": [
    #                                     {
    #                                         "version": "1.2.3"
    #                                     }
    #                                 ]
    #                             }
    #                         ]
    #         }
    
    output = BomTarget(ref="example/123", versions=[BomTargetVersionRange(version= "1.2.3")])

    config_data = {"ref": "ref","versions": ["version"]}
  
    
    csv_data = pd.Series({"ref":"example/123", "version": "1.2.3"})

    res = utils.get_affect(csv_data, config_data)

    assert res == output
    
def test_advisory():
    output = VulnerabilityAdvisory(title="google", url=XsUri("https://www.google.com/"))
    csv_data = pd.Series({"title":"google", "url":"https://www.google.com/"})
    config_data = {
            "title": "title",
            "url": "url"
        }
    
    res = utils.get_advisory(csv_data, config_data)
    assert res == output
    
def test_rating():
    output = VulnerabilityRating(
                                    source=VulnerabilitySource(name="google", url=XsUri("https://www.google.com/")),
                                    score=decimal.Decimal(4.1),
                                    severity = VulnerabilitySeverity("low"),
                                    method = VulnerabilityScoreSource("CVSSv2"),
                                    vector="foo",
                                    justification="bar"
                                )
    config_data = {
                        "source": {
                                    "url": "sourceurl",
                                    "name": "sourcename"
                                },
                        "score": "score",
                        "severity": "severity",
                        "method": "method",
                        "vector": "vector",
                        "justification": "justification"
                    }

    csv_data = pd.Series(
                            {
                                "sourceurl": "https://www.google.com/", 
                                "sourcename":"google", 
                                "score": 4.1, 
                                "severity":"low", 
                                "method":"CVSSv2",
                                "vector":"foo",
                                "justification":"bar"
                            
                            }
                        )
    res = utils.get_rating(csv_data, config_data)
    assert res == output

def test_reference():
    output = VulnerabilityReference(
        id = "123456",
        source=VulnerabilitySource(name="google", url=XsUri("https://www.google.com/"))
    )

    config_data = {
                        "id": "id",
                        "source": {
                            "url": "sourceurl",
                            "name": "sourcename"
                        }
                    }
    
    csv_data = pd.Series(
                            {
                                "sourceurl":"https://www.google.com/", 
                                "sourcename":"google", 
                                "id":"123456"
                            }
                        )
    
    res = utils.get_reference(csv_data, config_data)
    assert res == output

def test_get_val():
    output = "bar"
    config_data = {"foo":"foobar"}
    csv_data = pd.Series({"foobar":"bar"})
    res = utils.get_val("foo", csv_data, config_data)
    assert res == output

def test_vulnerability():
    output = Vulnerability()
    output.cwes = [123, 456]
    output.properties=[Property(name="check", value="pass")]
    output.tools = [Tool(name="Tool", version="1.2.3")]
    output.credits = VulnerabilityCredits(
                                organizations=[
                                                    OrganizationalEntity(
                                                                            name="OrgName",
                                                                            urls=[XsUri("https://www.google.com/")],
                                                                            contacts=[
                                                                                OrganizationalContact(
                                                                                    name="Name",
                                                                                    email="example_email@email.com",
                                                                                    phone="222-222-2222"
                                                                                )
                                                                            ]
                                                                        )
                                            ], 
                                individuals=[
                                                    OrganizationalContact(
                                                                            name="Name2",
                                                                            email="example_email@email.com",
                                                                            phone="222-222-2222"
                                                                        )
                                            ]
                            )
                    
    output.affects = [BomTarget(ref="example/123", versions=[BomTargetVersionRange(version= "1.2.3")])]
    output.advisories = [VulnerabilityAdvisory(title="google", url=XsUri("https://www.google.com/"))]
    output.ratings = [
                        VulnerabilityRating(
                                    source=VulnerabilitySource(name="google", url=XsUri("https://www.google.com/")),
                                    score=decimal.Decimal(4.1),
                                    severity = VulnerabilitySeverity("low"),
                                    method = VulnerabilityScoreSource("CVSSv2"),
                                    vector="foo",
                                    justification="bar"
                                    )
                    ]
    output.references = [
                            VulnerabilityReference(
                                                    id = "123456",
                                                    source=VulnerabilitySource(name="google", url=XsUri("https://www.google.com/"))
                                                    )
                        ]
    output.analysis = VulnerabilityAnalysis(state=ImpactAnalysisState.EXPLOITABLE, justification=ImpactAnalysisJustification.CODE_NOT_PRESENT)
    

    csv_data = pd.Series(
        {
            "state":"exploitable",
            "justification2":"code_not_present",
            "check": "pass",
            "orgname":"OrgName",
            "orgurl":"https://www.google.com/",
            "orgcontactname":"Name",
            "orgcontactemail":"example_email@email.com",
            "orgcontactphone":"222-222-2222",
            "individualname":"Name2",
            "individualemail":"example_email@email.com",
            "individualphone":"222-222-2222",
            "ref":"example/123", 
            "version": "1.2.3",
            "title":"google", 
            "url":"https://www.google.com/",
            "sourceurl": "https://www.google.com/", 
            "sourcename":"google", 
            "score": 4.1, 
            "severity":"low", 
            "method":"CVSSv2",
            "vector":"foo",
            "justification":"bar",
            "sourceurl":"https://www.google.com/", 
            "sourcename":"google", 
            "id":"123456",
            "tool_name": "Tool",
            "tool_version":"1.2.3",
            "cwes":"[CWE-123, 456]"
        }
    )


    config_data = {
        "cwes":"cwes",
        "properties":["check"],
        "analysis":{"state":"state", "justification": "justification2"},
        "tools":[
                    {
                        "name":"tool_name",
                        "version":"tool_version"
                    }
                ],
        "credits":{
                    "organizations": [
                                        {
                                            "bom-ref": None,
                                            "name": "orgname",
                                            "urls": ["orgurl"],
                                            "contact": [
                                                {
                                                    "bom-ref": None,
                                                    "name": "orgcontactname",
                                                    "email": "orgcontactemail",
                                                    "phone": "orgcontactphone"
                                                }
                                            ]
                                        }
                ],
                "individuals": [
                                    {
                                        "bom-ref": None,
                                        "name": "individualname",
                                        "email": "individualemail",
                                        "phone": "individualphone"
                                    }
                ]
            },
        "affects":[{"ref": "ref","versions": ["version"]}],
        "advisories":[{"title": "title","url": "url"}],
        "ratings":[
                    {
                        "source": {
                                    "url": "sourceurl",
                                    "name": "sourcename"
                                },
                        "score": "score",
                        "severity": "severity",
                        "method": "method",
                        "vector": "vector",
                        "justification": "justification"
                    }
                ],
        "references":[
                        {
                            "id": "id",
                            "source": {
                                "url": "sourceurl",
                                "name": "sourcename"
                            }
                        }
                    ]    
    }

    res = utils.get_vulnerability(csv_data, config_data)
    assert res.properties == output.properties
    assert res.tools == output.tools
    assert res.credits.organizations[0] == output.credits.organizations[0]
    assert res.credits.individuals[0] == output.credits.individuals[0]
    assert res.affects == output.affects
    assert res.advisories == output.advisories
    assert res.ratings == output.ratings
    assert res.references == output.references
    assert res.cwes == output.cwes
    assert res.analysis == output.analysis



    






    


