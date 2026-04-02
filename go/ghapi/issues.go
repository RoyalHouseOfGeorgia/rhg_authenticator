package ghapi

import (
	"context"
	"fmt"
	"net/http"
)

const maxIssueTitle = 256

// IssueResult holds the response from creating a GitHub issue.
type IssueResult struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// CreateIssue creates a new issue on the configured repository.
// The title is truncated to 256 characters for readability.
func (c *Client) CreateIssue(ctx context.Context, title, body string, labels []string) (IssueResult, error) {
	if len(title) > maxIssueTitle {
		// Walk backward to avoid splitting a multi-byte UTF-8 rune.
		n := maxIssueTitle
		for n > 0 && title[n]&0xC0 == 0x80 {
			n--
		}
		title = title[:n]
	}

	path := fmt.Sprintf("/repos/%s/%s/issues", c.Owner, c.Repo)
	reqBody := map[string]any{
		"title":  title,
		"body":   body,
		"labels": labels,
	}

	var issue IssueResult
	if err := c.doJSON(ctx, http.MethodPost, path, reqBody, &issue); err != nil {
		return IssueResult{}, err
	}
	return issue, nil
}
