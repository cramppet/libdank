#pragma once

/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or distribute
 * this software, either in source code form or as a compiled binary, for any
 * purpose, commercial or non-commercial, and by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors of this
 * software dedicate any and all copyright interest in the software to the
 * public domain. We make this dedication for the benefit of the public at large
 * and to the detriment of our heirs and successors. We intend this dedication
 * to be an overt act of relinquishment in perpetuity of all present and future
 * rights to this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#include <map>
#include <set>
#include <string>
#include <queue>
#include <vector>
#include <cstdint>
#include <cassert>

using namespace std;

class BigInteger
{
private:
	void trim();

public:
	typedef uint32_t Digit;
	typedef uint64_t Wigit;
	static const unsigned BITS = 32;

	// Digits are stored in little-endian 
	std::vector<Digit> digits;

	// Constructors

	BigInteger(Digit u = 0);
	BigInteger(const BigInteger& copy);
	BigInteger(std::vector<uint8_t> bytes); 

	// Operators

	BigInteger& operator= (const BigInteger& rhs);
	friend BigInteger operator+ (const BigInteger& u, const BigInteger& v);
	BigInteger& operator+= (const BigInteger& rhs);
	friend BigInteger operator- (const BigInteger& u, const BigInteger& v);
	BigInteger& operator-= (const BigInteger& rhs);
	friend bool operator< (const BigInteger& u, const BigInteger& v);
	friend bool operator>= (const BigInteger& u, const BigInteger& v);

	// Utility functions

	Digit to_uint() const;
	std::vector<uint8_t> to_bytes(int read) const; // Returns little-endian bytes
};

struct DFA;

struct NFA {
	struct State {
		bool final;
		map<unsigned char, set<size_t>> trans;
	};

	set<size_t> init;
	vector<State> pool;

	static NFA from_regex(const char* lo, const char* hi);

	void insert(size_t, unsigned char, size_t);
	void get_closure(set<size_t>& req) const;
	DFA determinize() const;

private:
	void _from_regex(size_t, size_t, const char*, const char*);
};

struct DFA {
	struct State {
		bool final;
		map<unsigned char, size_t> trans;
	};

	size_t init;
	vector<State> pool;

	uint32_t _fixed_slice;
	std::map<uint32_t, char> _sigma;
	std::map<char, uint32_t> _sigma_reverse;
	std::vector<std::vector<BigInteger>> _T;

	static DFA from_regex(const char*);

	void insert(size_t, unsigned char, size_t);
	string to_fst() const;
	NFA reverse() const;

	void buildTable(uint32_t fixed_slice);
	std::string unrank(BigInteger);
	BigInteger rank(const std::string);
	BigInteger getNumWordsInLanguage(const uint32_t, const uint32_t);
};

void NFA::insert(size_t s, unsigned char c, size_t t) {
	assert(s < pool.size());
	pool[s].trans[c].insert(t);
}

void NFA::get_closure(set<size_t>& req) const {
	const NFA& nfa = *this;
	queue<size_t> q;
	for (auto i = req.begin(); i != req.end(); i++)
		q.push(*i);
	while (q.size()) {
		size_t u = q.front();
		q.pop();
		auto x = nfa.pool[u].trans.find(0);
		if (x == nfa.pool[u].trans.end())
			continue;
		for (auto i = x->second.begin(); i != x->second.end(); i++)
			if (req.find(*i) == req.end()) {
				req.insert(*i);
				q.push(*i);
			}
	}
}

// Thompson's construction algorithm BEGIN

NFA NFA::from_regex(const char* lo, const char* hi) {
	NFA nfa;
	nfa.pool.clear();
	nfa.pool.push_back(NFA::State());
	nfa.pool.push_back(NFA::State());
	nfa.pool[1].final = 1;
	nfa.init.clear();
	nfa.init.insert(0);
	nfa._from_regex(0, 1, lo, hi);
	nfa.get_closure(nfa.init);
	return nfa;
}

void NFA::_from_regex(size_t s, size_t t, const char* lo, const char* hi) {
	NFA& nfa = *this;
	if (hi - lo == 1) {
		nfa.insert(s, *lo, t);
		return;
	}
	if (hi - lo == 2 && *lo == '\\') {
		nfa.insert(s, *(lo + 1), t);
		return;
	}
	const char* option = lo;
	const char* concatenation = lo;
	size_t _ = 0;
	for (const char* i = lo; i != hi; ++i)
		switch (*i) {
		case '\\':
			if (!_)
				concatenation = i;
			++i;
			break;
		case '(':
			if (!_)
				concatenation = i;
			++_;
			break;
		case ')':
			assert(_);
			--_;
			break;
		case '|':
			if (!_)
				option = i;
			break;
		case '?':
			break;
		case '*':
			break;
		case '+':
			break;
		default:
			if (!_)
				concatenation = i;
		}
	assert(_ == 0);
	if (option != lo) {
		size_t i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(s, 0, i0);
		nfa.insert(i1, 0, t);
		_from_regex(i0, i1, lo, option);
		i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(s, 0, i0);
		nfa.insert(i1, 0, t);
		_from_regex(i0, i1, option + 1, hi);
	}
	else if (concatenation != lo) {
		size_t i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(i0, 0, i1);
		_from_regex(s, i0, lo, concatenation);
		_from_regex(i1, t, concatenation, hi);
	}
	else if (*(hi - 1) == '?') {
		size_t i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(s, 0, i0);
		nfa.insert(s, 0, t);
		nfa.insert(i1, 0, t);
		_from_regex(i0, i1, lo, hi - 1);
	}
	else if (*(hi - 1) == '*') {
		size_t i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(s, 0, i0);
		nfa.insert(s, 0, t);
		nfa.insert(i1, 0, i0);
		nfa.insert(i1, 0, t);
		_from_regex(i0, i1, lo, hi - 1);
	}
	else if (*(hi - 1) == '+') {
		size_t i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(i0, 0, i1);
		_from_regex(s, i0, lo, hi - 1);
		s = i1;
		i0 = nfa.pool.size(), i1 = nfa.pool.size() + 1;
		nfa.pool.push_back(NFA::State());
		nfa.pool.push_back(NFA::State());
		nfa.insert(s, 0, i0);
		nfa.insert(s, 0, t);
		nfa.insert(i1, 0, i0);
		nfa.insert(i1, 0, t);
		_from_regex(i0, i1, lo, hi - 1);
	}
	else {
		assert(*lo == '(' && *(hi - 1) == ')');
		_from_regex(s, t, lo + 1, hi - 1);
	}
}

// Thompson's construction algorithm END

// Powerset construction
DFA NFA::determinize() const {
	const NFA& nfa = *this;
	DFA dfa;
	map<set<size_t>, size_t> m;
	queue<set<size_t>> q;
	vector<bool> inQ;
	dfa.init = 0;
	dfa.pool.clear();
	dfa.pool.push_back(DFA::State());
	for (auto i = nfa.init.begin(); i != nfa.init.end(); i++)
		if (nfa.pool[*i].final) {
			dfa.pool[0].final = 1;
			break;
		}
	m[nfa.init] = 0;
	q.push(nfa.init);
	inQ.push_back(1);
	while (q.size()) {
		set<size_t> u0 = q.front();
		size_t u1 = m[u0];
		map<unsigned char, set<size_t>> _;
		q.pop();
		inQ[u1] = 0;
		for (auto i = u0.begin(); i != u0.end(); ++i)
			for (auto j = nfa.pool[*i].trans.upper_bound(0);
				j != nfa.pool[*i].trans.end(); j++)
				_[j->first].insert(j->second.begin(), j->second.end());
		for (auto i = _.begin(); i != _.end(); i++) {
			nfa.get_closure(i->second);
			auto __ = m.find(i->second);
			if (__ == m.end()) {
				size_t v1 = dfa.pool.size();
				dfa.pool.push_back(DFA::State());
				dfa.insert(u1, i->first, v1);
				m[i->second] = v1;
				q.push(i->second);
				inQ.push_back(1);
				for (auto j = i->second.begin(); j != i->second.end(); j++)
					if (nfa.pool[*j].final) {
						dfa.pool.back().final = 1;
						break;
					}
			}
			else
				dfa.insert(u1, i->first, __->second);
		}
	}
	return dfa;
}

void DFA::insert(size_t s, unsigned char c, size_t t) {
	assert(s < pool.size());
	assert(pool[s].trans.find(c) == pool[s].trans.end());
	pool[s].trans[c] = t;
}

// string DFA::to_fst() const {
// 	stringstream ss;
// 	for (size_t i = 0; i < pool.size(); i++) {
// 		for (auto j = pool[i].trans.begin(); j != pool[i].trans.end(); j++) {
// 			ss << i << "\t" << j->second << "\t" << (int)j->first << "\t" << (int)j->first << endl;
// 		}
// 		if (pool[i].final)
// 			ss << i << endl;
// 	}
// 	return ss.str();
// }

NFA DFA::reverse() const {
	NFA nfa;
	const DFA& dfa = *this;
	nfa.init.clear();
	nfa.pool.assign(dfa.pool.size(), NFA::State());
	for (size_t i = 0; i < dfa.pool.size(); i++) {
		for (auto j = dfa.pool[i].trans.begin(); j != dfa.pool[i].trans.end(); j++)
			nfa.insert(j->second, j->first, i);
		if (dfa.pool[i].final)
			nfa.init.insert(i);
	}
	nfa.pool[dfa.init].final = 1;
	return nfa;
}

// Brzozowski's algorithm
DFA DFA::from_regex(const char* regex) {
	size_t len = strlen(regex);
	return move(NFA::from_regex(regex, regex + len)
		.determinize()
		.reverse()
		.determinize()
		.reverse()
		.determinize());
}

void DFA::buildTable(uint32_t fixed_slice) {
	uint32_t i = 0, q = 0, a = 0;
	std::vector<char> symbols;
	size_t _num_states = pool.size();

	this->_fixed_slice = fixed_slice;

	_T.resize(_num_states);
	for (q = 0; q < _num_states; q++) {
		_T.at(q).resize(_fixed_slice + 1);
		for (i = 0; i <= _fixed_slice; i++) {
			_T.at(q).at(i) = 0;
		}
	}

	for (i = 0, q = 0; i < pool.size(); i++) {
		if (pool[i].final) {
			_T.at(i).at(0) = 1;
		}
		for (auto j = pool[i].trans.begin(); j != pool[i].trans.end(); j++) {
			if (find(symbols.begin(), symbols.end(), j->first) == symbols.end()) {
				this->_sigma.insert(std::pair<uint32_t, char>(q, j->first));
				this->_sigma_reverse.insert(std::pair<char, uint32_t>(j->first, q));
				symbols.push_back(j->first);
				q += 1;
			}
		}
	}

	// Walk through our table _T we want each entry _T.at(q).at(i) to contain the
	// number of strings that start from state q, terminate in a final state, and
	// are of length i

	for (i = 1; i <= _fixed_slice; i++) {
		for (q = 0; q < pool.size(); q++) {
			for (auto a = pool[q].trans.begin(); a != pool[q].trans.end(); a++) {
				uint32_t _state = a->second;
				_T.at(q).at(i) += _T.at(_state).at(i - 1);
			}
		}
	}
}

BigInteger DFA::getNumWordsInLanguage(const uint32_t lo, const uint32_t hi)
{
	// verify min_word_length <= max_word_length <= _fixed_slice
	assert(0 <= lo);
	assert(lo <= hi);
	assert(hi <= _fixed_slice);

	// count the number of words in the language of length
	// at least min_word_length and no greater than max_word_length
	BigInteger num_words = 0;

	for (uint32_t len = lo; len <= hi; len++) {
		num_words += _T.at(0).at(len);
	}

	return num_words;
}

std::string DFA::unrank(BigInteger c_in) {
	std::string retval;
	BigInteger words_in_slice = getNumWordsInLanguage(_fixed_slice, _fixed_slice);

	if (words_in_slice < c_in) {
		// TODO: Handle former exception
		//throw invalid_unrank_input;
		return retval;
	}

	BigInteger c = c_in;
	uint32_t i = 0;
	uint32_t q = 0;
	uint32_t char_cursor = 0;
	uint32_t state = 0;
	BigInteger char_index = 0;

	for (i = 1; i <= _fixed_slice; i++) {
		char_cursor = 0;
		// Workaround because we don't initialize non-existant transitions to a dead state
		while (pool[q].trans.find(_sigma.at(char_cursor)) == pool[q].trans.end()) {
			char_cursor += 1;
		}
		state = pool[q].trans.at(_sigma.at(char_cursor));
		while (c >= _T.at(state).at(_fixed_slice - i)) {
			c -= _T.at(state).at(_fixed_slice - i);
			char_cursor += 1;
      if (pool[q].trans.find(_sigma.at(char_cursor)) != pool[q].trans.end()) {
			  state = pool[q].trans.at(_sigma.at(char_cursor));
      }
		}
		retval += _sigma.at(char_cursor);
		q = state;
	}

	return retval;
}

BigInteger DFA::rank(const std::string X) {
	BigInteger retval = 0;

	// walk the DFAEncoder, adding values from _T to c
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t n = X.size();
	uint32_t symbol_as_int = 0;
	uint32_t q = 0;
	uint32_t state = 0;
	BigInteger tmp = 0;

	for (i = 1; i <= n; i++) {
		if (_sigma_reverse.find(X.at(i - 1)) == _sigma_reverse.end()) {
			// TODO: Handle error: symbol not found
			return retval;
		}
		symbol_as_int = _sigma_reverse.at(X.at(i - 1));
		for (j = 1; j <= symbol_as_int; j++) {
			if (pool[q].trans.find(_sigma.at(j - 1)) != pool[q].trans.end()) {
				state = pool[q].trans.at(_sigma.at(j - 1));
				retval += _T.at(state).at(n - i);
			}
		}
		q = pool[q].trans.at(_sigma.at(symbol_as_int));
	}

	return retval;
}

BigInteger::BigInteger(Digit u) : digits(1, u)
{
	// empty
}

BigInteger::BigInteger(const BigInteger& copy) : digits(copy.digits)
{
	// empty
}

BigInteger::BigInteger(std::vector<uint8_t> bytes) {
	// Collect up to four bytes into 1 digit per iteration
	Digit n;

	for (int i = 0; i < bytes.size(); i++) {
		n = 0;

		if (i + 3 < bytes.size()) {
			n = (bytes[i + 3] << 24) | (bytes[i + 2] << 16) | (bytes[i + 1] << 8) | bytes[i];
			// Make sure we don't examine these again
			i += 3;
		}

		// If we don't have enough to fill 1 word-size, then consume as many as possible
		else {
			do {
				n |= bytes[i++];
				if (i < bytes.size()) {
					n <<= 8;
				}
			} while (i < bytes.size());
		}

		this->digits.push_back(n);
	}
}

std::vector<uint8_t> BigInteger::to_bytes(int read) const
{
	std::vector<uint8_t> ret;
	uint8_t j, k, m, n;
	uint32_t d;

	for (int i = 0; i < digits.size(); i++, read -= 4) {
		d = digits[i];

		j = d         & 0xFF;
		k = (d >>  8) & 0xFF;
		m = (d >> 16) & 0xFF;
		n = (d >> 24) & 0xFF;

    ret.push_back(j);
    ret.push_back(k);
    ret.push_back(m);
    ret.push_back(n);
	}

  while (read-- > 0) ret.push_back(0);
	return ret;
}

BigInteger& BigInteger::operator= (const BigInteger& rhs)
{
	digits = rhs.digits;
	return *this;
}

BigInteger operator+ (const BigInteger& u, const BigInteger& v)
{
	BigInteger w(u);
	w += v;
	return w;
}

BigInteger& BigInteger::operator+= (const BigInteger& rhs)
{
	const size_t n = rhs.digits.size();
	size_t j = 0;
	Wigit k = 0;

	if (digits.size() < n)
	{
		digits.resize(n, 0);
	}

	for (; j < n; ++j)
	{
		k = k + digits[j] + rhs.digits[j];
		digits[j] = static_cast<Digit>(k);
		k >>= BITS;
	}

	for (; k != 0 && j < digits.size(); ++j)
	{
		k += digits[j];
		digits[j] = static_cast<Digit>(k);
		k >>= BITS;
	}

	if (k != 0)
	{
		digits.push_back(1);
	}

	return *this;
}

BigInteger operator- (const BigInteger& u, const BigInteger& v)
{
	BigInteger w(u);
	w -= v;
	return w;
}

BigInteger& BigInteger::operator-= (const BigInteger& rhs)
{
	if ((*this) < rhs)
	{
		// TODO: Find another way to deal with errors
		//throw std::underflow_error("Error: Unsigned::underflow");
		return *this;
	}
	size_t j = 0;
	Wigit k = 0;
	for (; j < rhs.digits.size(); ++j)
	{
		k = k + digits[j] - rhs.digits[j];
		digits[j] = static_cast<Digit>(k);
		k = ((k >> BITS) ? -1 : 0);
	}
	for (; k != 0 && j < digits.size(); ++j)
	{
		k += digits[j];
		digits[j] = static_cast<Digit>(k);
		k = ((k >> BITS) ? -1 : 0);
	}
	trim();
	return *this;
}

bool operator< (const BigInteger& u, const BigInteger& v)
{
	const size_t m = u.digits.size();
	size_t n = v.digits.size();
	if (m != n)
	{
		return (m < n);
	}
	for (--n; n != 0 && u.digits[n] == v.digits[n]; --n);
	return (u.digits[n] < v.digits[n]);
}

bool operator>= (const BigInteger& u, const BigInteger& v)
{
	return !(u < v);
}

BigInteger::Digit BigInteger::to_uint() const
{
	return digits[0];
}

void BigInteger::trim()
{
	while (digits.back() == 0 && digits.size() > 1)
	{
		digits.pop_back();
	}
}
