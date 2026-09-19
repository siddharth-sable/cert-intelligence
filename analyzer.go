package main

import (
	"math"
	"strings"
)

var TargetBrands = []string{
	"paypal", "google", "binance", "coinbase", "github", 
	"microsoft", "apple", "netflix", "metron", "meta",
}

var SuspiciousKeywords = []string{
	"login", "verify", "auth", "security", "account", 
	"support", "update", "wallet", "portal", "confirm",
}

type AnalysisResult struct {
	Domain     string   `json:"domain"`
	RiskScore  int      `json:"risk_score"`
	Reasons    []string `json:"reasons"`
	Entropy    float64  `json:"entropy"`
	MatchedBrand string `json:"matched_brand,omitempty"`
}

// CalculateShannonEntropy calculates information entropy of string
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	charMap := make(map[rune]float64)
	for _, char := range s {
		charMap[char]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range charMap {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// LevenshteinDistance calculates edit distance between two strings
func LevenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)

	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}

	matrix := make([][]int, n+1)
	for i := range matrix {
		matrix[i] = make([]int, m+1)
		matrix[i][0] = i
	}
	for j := 1; j <= m; j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][i-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}

	return matrix[n][m]
}

func min(nums ...int) int {
	m := nums[0]
	for _, n := range nums {
		if n < m {
			m = n
		}
	}
	return m
}

// AnalyzeDomain scores a single domain name
func AnalyzeDomain(domain string) AnalysisResult {
	cleanDomain := strings.ToLower(strings.TrimPrefix(domain, "*."))
	parts := strings.Split(cleanDomain, ".")
	mainPart := parts[0]

	score := 0
	reasons := []string{}
	matchedBrand := ""

	// 1. Check Levenshtein Distance for Typosquatting
	for _, brand := range TargetBrands {
		if strings.Contains(mainPart, brand) && mainPart != brand {
			score += 40
			reasons = append(reasons, "Contains brand name in combo domain: "+brand)
			matchedBrand = brand
			break
		}

		dist := LevenshteinDistance(mainPart, brand)
		if dist > 0 && dist <= 2 {
			score += 50
			reasons = append(reasons, "Typosquatting detected for brand: "+brand)
			matchedBrand = brand
			break
		}
	}

	// 2. Suspicious Keyword Combinations
	keywordCount := 0
	for _, kw := range SuspiciousKeywords {
		if strings.Contains(cleanDomain, kw) {
			keywordCount++
		}
	}
	if keywordCount > 0 {
		addedScore := keywordCount * 15
		score += addedScore
		reasons = append(reasons, "Contains suspicious security keywords")
	}

	// 3. Shannon Entropy
	entropy := CalculateShannonEntropy(mainPart)
	if entropy >= 3.8 && len(mainPart) > 10 {
		score += 25
		reasons = append(reasons, "High string entropy (randomness)")
	}

	// 4. Excessive Subdomains
	if len(parts) > 3 {
		score += 15
		reasons = append(reasons, "Excessive subdomain depth")
	}

	if score > 100 {
		score = 100
	}

	return AnalysisResult{
		Domain:       domain,
		RiskScore:    score,
		Reasons:      reasons,
		Entropy:      entropy,
		MatchedBrand: matchedBrand,
	}
}