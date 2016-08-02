package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/tomnomnom/linkheader"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	GHE_API                 = "/api/v3"
	GITHUB_ACCESS_TOKEN     = Name + "access_token"
	GITHUB_API              = "https://api.github.com"
	GITHUB_DEFAULT_HOSTNAME = "https://github.com"
)

type GithubClient struct {
	httpClient *http.Client
	config     *GithubConfig
}

func (g *GithubClient) getAccessToken(code string) (string, error) {
	form := url.Values{}
	form.Add("client_id", g.config.ClientID)
	form.Add("client_secret", g.config.ClientSecret)
	form.Add("code", code)

	url := g.getUrl("TOKEN")

	resp, err := g.postToGithub(url, form)
	if err != nil {
		log.Errorf("Github getAccessToken: received error from github, err: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Decode the response
	var respMap map[string]interface{}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Github getAccessToken: received error reading response body, err: %v", err)
		return "", err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		log.Errorf("Github getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", err
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		log.Errorf("Received Error from github %v, description from github %v", respMap["error"], desc)
		return "", fmt.Errorf("Received Error from github %v, description from github %v", respMap["error"], desc)
	}

	acessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}
	return acessToken, nil
}

func (g *GithubClient) getGithubUser(githubAccessToken string) (GithubAccount, error) {

	url := g.getUrl("USER_INFO")
	log.Debugf("url %v", url)
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubUser: received error from github, err: %v", err)
		return GithubAccount{}, err
	}
	defer resp.Body.Close()
	var githubAcct GithubAccount

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubUser: error reading response, err: %v", err)
		return GithubAccount{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubUser: error unmarshalling response, err: %v", err)
		return GithubAccount{}, err
	}

	return githubAcct, nil
}

func (g *GithubClient) getGithubOrgs(githubAccessToken string) ([]GithubAccount, error) {
	var orgs []GithubAccount
	url := g.getUrl("ORG_INFO")
	responses, err := g.paginateGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubOrgs: received error from github, err: %v", err)
		return orgs, err
	}

	for _, response := range responses {
		defer response.Body.Close()
		var orgObjs []GithubAccount
		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorf("Github getGithubOrgs: error reading the response from github, err: %v", err)
			return orgs, err
		}
		if err := json.Unmarshal(b, &orgObjs); err != nil {
			log.Errorf("Github getGithubOrgs: received error unmarshalling org array, err: %v", err)
			return orgs, err
		} else {
			for _, orgObj := range orgObjs {
				orgs = append(orgs, orgObj)
			}
		}

	}

	return orgs, nil
}

func (g *GithubClient) getGithubTeams(githubAccessToken string) ([]GithubAccount, error) {
	var teams []GithubAccount
	url := g.getUrl("TEAMS")
	responses, err := g.paginateGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubTeams: received error from github, err: %v", err)
		return teams, err
	}
	for _, response := range responses {
		defer response.Body.Close()
		teamObjs, err := g.getTeamInfo(response)

		if err != nil {
			log.Errorf("Github getGithubTeams: received error unmarshalling teams array, err: %v", err)
			return teams, err
		} else {

			for _, teamObj := range teamObjs {
				teams = append(teams, teamObj)
			}
		}
	}
	return teams, nil
}

func (g *GithubClient) getTeamInfo(response *http.Response) ([]GithubAccount, error) {
	var teams []GithubAccount
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Github getTeamInfo: error reading the response from github, err: %v", err)
		return teams, err
	}
	var teamObjs []GithubTeam
	if err := json.Unmarshal(b, &teamObjs); err != nil {
		log.Errorf("Github getTeamInfo: received error unmarshalling team array, err: %v", err)
		return teams, err
	} else {
		url := g.getUrl("TEAM_PROFILE")
		for _, team := range teamObjs {
			teamAcct := GithubAccount{}
			team.toGithubAccount(url, &teamAcct)
			teams = append(teams, teamAcct)
		}
	}
	return teams, nil
}

func (g *GithubClient) getTeamById(githubAccessToken string, id string) (GithubAccount, error) {
	var teamAcct GithubAccount
	url := g.getUrl("TEAM") + id
	response, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getTeamById: received error from github, err: %v", err)
		return teamAcct, err
	}
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Github getTeamById: error reading the response from github, err: %v", err)
		return teamAcct, err
	}
	var teamObj GithubTeam
	if err := json.Unmarshal(b, &teamObj); err != nil {
		log.Errorf("Github getTeamInfo: received error unmarshalling team array, err: %v", err)
		return teamAcct, err
	} else {
		url := g.getUrl("TEAM_PROFILE")
		teamObj.toGithubAccount(url, &teamAcct)
	}
	return teamAcct, nil
}

func (g *GithubClient) paginateGithub(githubAccessToken string, url string) ([]*http.Response, error) {
	var responses []*http.Response

	response, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		return responses, err
	}
	responses = append(responses, response)
	nextUrl := g.nextGithubPage(response)
	for nextUrl != "" {
		response, err = g.getFromGithub(githubAccessToken, nextUrl)
		if err != nil {
			return responses, err
		}
		responses = append(responses, response)
		nextUrl = g.nextGithubPage(response)
	}

	return responses, nil
}

func (g *GithubClient) nextGithubPage(response *http.Response) string {
	header := response.Header.Get("link")

	if header != "" {
		links := linkheader.Parse(header)
		for _, link := range links {
			if link.Rel == "next" {
				return link.URL
			}
		}
	}

	return ""
}

func (g *GithubClient) getGithubUserByName(username string, githubAccessToken string) (GithubAccount, error) {

	_, err := g.getGithubOrgByName(username, githubAccessToken)
	if err == nil {
		return GithubAccount{}, fmt.Errorf("There is a org by this name, not looking fo the user entity by name %v", username)
	}

	username = URLEncoded(username)
	url := g.getUrl("USERS") + username

	log.Debugf("url %v", url)
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubUserByName: received error from github, err: %v", err)
		return GithubAccount{}, err
	}
	defer resp.Body.Close()
	var githubAcct GithubAccount

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubUserByName: error reading response, err: %v", err)
		return GithubAccount{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubUserByName: error unmarshalling response, err: %v", err)
		return GithubAccount{}, err
	}

	return githubAcct, nil
}

func (g *GithubClient) getGithubOrgByName(org string, githubAccessToken string) (GithubAccount, error) {

	org = URLEncoded(org)
	url := g.getUrl("ORGS") + org

	log.Debugf("url %v", url)
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubOrgByName: received error from github, err: %v", err)
		return GithubAccount{}, err
	}
	defer resp.Body.Close()
	var githubAcct GithubAccount

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubOrgByName: error reading response, err: %v", err)
		return GithubAccount{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubOrgByName: error unmarshalling response, err: %v", err)
		return GithubAccount{}, err
	}

	return githubAcct, nil
}

func (g *GithubClient) getUserOrgById(id string, githubAccessToken string) (GithubAccount, error) {

	url := g.getUrl("USER_INFO") + "/" + id

	log.Debugf("url %v", url)
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getUserOrgById: received error from github, err: %v", err)
		return GithubAccount{}, err
	}
	defer resp.Body.Close()
	var githubAcct GithubAccount

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Github getUserOrgById: error reading response, err: %v", err)
		return GithubAccount{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getUserOrgById: error unmarshalling response, err: %v", err)
		return GithubAccount{}, err
	}

	return githubAcct, nil
}

/* TODO non-exact search
func (g *GithubClient) searchGithub(githubAccessToken string, url string) []map[string]interface{} {
	log.Debugf("url %v",url)
	resp, err := g.getFromGithub(githubAccessToken, url)
}


    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchGithub(String url) {
        try {
            HttpResponse res = getFromGithub(githubTokenUtils.getAccessToken(), url);
            //TODO:Finish implementing search.
            Map<String, Object> jsonData = jsonMapper.readValue(res.getEntity().getContent());
            return (List<Map<String, Object>>) jsonData.get("items");
        } catch (IOException e) {
            //TODO: Proper Error Handling.
            return new ArrayList<>();
        }
    }

*/

//URLEncoded encodes the string
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		log.Errorf("Error encoding the url: %s , error: %v", str, err)
		return str
	}
	return u.String()
}

func (g *GithubClient) postToGithub(url string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		log.Error(err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Error("Received error from github: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (g *GithubClient) getFromGithub(githubAccessToken string, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err)
	}
	req.Header.Add("Authorization", "token "+githubAccessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Error("Received error from github: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return resp, fmt.Errorf("Request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return resp, nil
}

func (g *GithubClient) getUrl(endpoint string) string {

	var hostName, apiEndpoint, toReturn string

	if g.config.Hostname != "" {
		hostName = g.config.Scheme + g.config.Hostname
		apiEndpoint = g.config.Scheme + g.config.Hostname + GHE_API
	} else {
		hostName = GITHUB_DEFAULT_HOSTNAME
		apiEndpoint = GITHUB_API
	}

	switch endpoint {
	case "API":
		toReturn = apiEndpoint
	case "TOKEN":
		toReturn = hostName + "/login/oauth/access_token"
	case "USERS":
		toReturn = apiEndpoint + "/users/"
	case "ORGS":
		toReturn = apiEndpoint + "/orgs/"
	case "USER_INFO":
		toReturn = apiEndpoint + "/user"
	case "ORG_INFO":
		toReturn = apiEndpoint + "/user/orgs?per_page=1"
	case "USER_PICTURE":
		toReturn = "https://avatars.githubusercontent.com/u/" + endpoint + "?v=3&s=72"
	case "USER_SEARCH":
		toReturn = apiEndpoint + "/search/users?q="
	case "TEAM":
		toReturn = apiEndpoint + "/teams/"
	case "TEAMS":
		toReturn = apiEndpoint + "/user/teams?per_page=100"
	case "TEAM_PROFILE":
		toReturn = hostName + "/orgs/%s/teams/%s"
	default:
		toReturn = apiEndpoint
	}

	return toReturn
}
