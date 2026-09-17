import { assert } from 'chai'
import { describe, it } from 'mocha'
import sinon from 'sinon'
import { MapSettingsRepository } from 'helix-auth-svc/lib/common/data/repositories/MapSettingsRepository.js'
import { HelixEntityRepository } from 'helix-auth-svc/lib/features/scim/data/repositories/HelixEntityRepository.js'
import { User } from 'helix-auth-svc/lib/features/scim/domain/entities/User.js'

describe('HelixEntity repository password generation', function () {
  function setup(enabled) {
    const settingsRepository = new MapSettingsRepository()
    if (enabled !== undefined) {
      settingsRepository.set('USER_AUTO_GEN_PASSWD', enabled)
    }
    const repository = new HelixEntityRepository({
      getProvisioningServers: () => [],
      settingsRepository
    })
    const cmd = sinon.stub().resolves({})
    cmd.withArgs('user -i -f').resolves({ info: [{ data: 'User alice saved.' }] })
    cmd.withArgs('key scim-user-alice').resolves({ stat: [{ value: '0' }] })
    sinon.stub(repository, 'makeP4').resolves({ cmd })
    const user = new User('alice', 'alice@example.com', 'Alice')
    return { repository, cmd, user }
  }

  it('generates a fresh password without exposing it in the user', async function () {
    const { repository, cmd, user } = setup('true')
    const first = await repository.addUser(user)
    const second = await repository.addUser(user)
    const calls = cmd.getCalls().filter(call => call.args[0] === 'passwd alice')
    assert.lengthOf(calls, 2)
    const passwords = calls.map(call => {
      const [password, confirmation] = call.args[1].split('\n')
      assert.equal(password, confirmation)
      assert.isAtLeast(password.length, 32)
      for (const pattern of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]) {
        assert.match(password, pattern)
      }
      return password
    })
    assert.notEqual(passwords[0], passwords[1])
    assert.isNotOk(user.password)
    assert.isNull(first.password)
    assert.isNull(second.password)
  })

  for (const enabled of [undefined, 'false', '']) {
    it(`does not generate a password when the setting is ${String(enabled)}`, async function () {
      const { repository, cmd, user } = setup(enabled)
      await repository.addUser(user)
      assert.isFalse(cmd.calledWith('passwd alice'))
    })
  }

  it('preserves an explicitly supplied password', async function () {
    const { repository, cmd, user } = setup('true')
    user.password = 'Supplied-password-123!'
    const result = await repository.addUser(user)
    assert.isTrue(cmd.calledWith('passwd alice', `${user.password}\n${user.password}`))
    assert.isNull(result.password)
  })
})
