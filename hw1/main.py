import math
import platform
import re
import collections
import asyncio
import aiohttp
import time


class Parser:
    def __init__(self, org, session, auth):
        self.org = org
        self.session = session
        self.result = collections.Counter()
        self.auth = auth
        self.repos = []

    def __str__(self):
        return str(self.result.most_common(100))

    async def parse(self):
        futures = []
        url = f'https://api.github.com/orgs/{self.org}'
        repos_json = await self.get_json_from_url(url)
        amount = math.ceil(repos_json['public_repos'] / 100)
        repos_array = await self.get_repositories(amount)
        for repo in repos_array:
            futures.append(self.get_emails_by_repository(repo))
        for future in asyncio.as_completed(futures):
            self.result.update(await future)

    async def get_emails_by_repository(self, repository):
        ans_arr = []
        futures = []
        request_site = f'https://api.github.com/repos/{self.org}/{repository}'
        print(f'started {repository}')
        async_commits_request_site = await self.get_json_from_url(request_site)
        commits_request_site = async_commits_request_site['commits_url'][:-6] + '?per_page=100'
        amount_of_pages = await self.get_amount_of_pages_100(commits_request_site)
        range_for_commits = range(1, amount_of_pages + 1)
        for i in range_for_commits:
            futures.append(self.get_emails_by_commit_page(i, repository))
        for future in asyncio.as_completed(futures):
            ans_arr += await future
        print(f'finished {repository}')
        return ans_arr

    async def get_amount_of_pages_100(self, site):
        async with self.session.get(site, auth=aiohttp.BasicAuth(self.auth[0], self.auth[1])) as response:
            if len(response.links) == 0:
                return 1
            last_url = str(response.links.get('last').get('url'))
            return int(last_url[last_url.rindex('=') + 1:])

    async def get_emails_by_commit_page(self, amount, repository):
        ans_arr = []
        futures = []
        text = f'https://api.github.com/repos/{self.org}/{repository}/commits?per_page=100&page={amount}'
        request = await self.get_json_from_url(text)  # async request
        for i in request:
            if type(i) == str:
                break
            futures.append(self.get_emails_by_100_commits(i))
        for future in futures:
            ans = await future
            if ans:
                ans_arr.append(ans)
        return ans_arr

    async def get_emails_by_100_commits(self, commit):
        if ('commit' in commit.keys()) and (not (re.search('Merge pull request #', commit['commit']['message']))):
            return commit['commit']['author']['email']
        return

    async def get_repositories(self, amount):
        repos_array = []
        for i in range(1, amount+1):
            base = f'https://api.github.com/orgs/{self.org}/repos?per_page=100&page={i}'
            repositories = await self.get_json_from_url(base)
            for repository in repositories:
                repos_array.append(repository['name'])
        self.repos = repos_array
        return repos_array

    async def get_json_from_url(self,
                                url: str):
        async with self.session.get(url, auth=aiohttp.BasicAuth(self.auth[0], self.auth[1])) as response:
            return await response.json()


async def main(org, auth):
    async with aiohttp.ClientSession() as session:
        parser = Parser(org=org, auth=auth, session=session)
        await parser.parse()
        for i, tup in enumerate(parser.result.most_common(100)):
            print(f'{i+1}) {tup[0]} - {tup[1]}')

if __name__ == '__main__':
    org = 'twitter'
    print('Enter github nickname')
    nickname = input()
    print('Enter guthub SSH key')
    key = input()
    auth = (nickname, key)
    time_start = time.time()
    repos_array = []
    ans_arr = []
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main(org, auth))